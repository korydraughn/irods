from __future__ import print_function
import contextlib
import copy
import glob
import itertools
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

from collections import OrderedDict

import psutil

from .configuration import IrodsConfig
from . import lib
from . import paths
from . import upgrade_configuration

from .exceptions import IrodsError, IrodsWarning

class IrodsController(object):
    def __init__(self, irods_config=IrodsConfig()):
        self.config = irods_config

    def check_config(self):
        # load the configuration to ensure it exists
        _ = self.config.server_config
        _ = self.config.version

    @property
    def server_binaries(self):
        return [
            self.config.server_executable,
            self.config.agent_executable,
            self.config.rule_engine_executable
        ]

    def get_server_pid(self):
        try:
            # Use of this python script assumes the PID file is located in <prefix>/var/run/irods.
            pid_file = os.path.join(paths.runstate_directory(), 'irods', 'irods-server.pid')
            if os.path.exists(pid_file):
                with open(pid_file, 'r') as f:
                    pid = int(f.readline().strip())
                    # If the user executing this python script does not have permission to send
                    # signals to the PID, an OSError exception will be raised indicating why.
                    os.kill(pid, 0)
                    return pid

        except (ProcessLookupError, PermissionError):
            return None

    def get_server_proc(self):
        server_pid = self.get_server_pid()
        if server_pid is None:
            return None

        # lib.get_server_pid() does not have access to self.config, so cannot
        # check the pid from the pidfile against self.config.server_executable,
        # only that a process with that pid exists. The possibility remains
        # that the pid may have been recycled.
        if server_pid >= 0:
            try:
                server_proc = psutil.Process(server_pid)
                if server_proc.exe() and os.path.samefile(self.config.server_executable, server_proc.exe()):
                    return server_proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return None

        return None

    def upgrade(self):
        l = logging.getLogger(__name__)
        l.debug('Calling upgrade on IrodsController')

        if upgrade_configuration.requires_upgrade(self.config):
            upgrade_configuration.upgrade(self.config)

        if self.config.is_provider:
            from . import database_interface
            database_interface.run_catalog_update(self.config)

    def start(self, write_to_stdout=False, test_mode=False):
        l = logging.getLogger(__name__)
        l.debug('Calling start on IrodsController')

        cmd = [self.config.server_executable]

        env_var_name = 'IRODS_ENABLE_TEST_MODE'
        if test_mode or (env_var_name in os.environ and os.environ[env_var_name] == '1'):
            cmd.append('-t')

        if write_to_stdout:
            l.info('Starting iRODS server ...')
            cmd.append('--stdout')
            lib.execute_command(cmd,
                                stdout=sys.stdout,
                                stderr=sys.stdout,
                                cwd=self.config.server_bin_directory,
                                env=self.config.execution_environment)
        else:
            l.info('Starting iRODS server as a daemon ...')
            cmd.append('-d')
            lib.execute_command(cmd,
                                cwd=self.config.server_bin_directory,
                                env=self.config.execution_environment)

    def stop(self, timeout=20, graceful=False):
        l = logging.getLogger(__name__)
        self.config.clear_cache()
        l.debug('Calling stop on IrodsController')

        server_pid = self.get_server_pid()
        if server_pid is None:
            l.info('iRODS server is not running')
            return

        l.info('Stopping iRODS server...')
        os.kill(server_pid, signal.SIGTERM if not graceful else signal.SIGQUIT)

    def restart(self, write_to_stdout=False, test_mode=False):
        l = logging.getLogger(__name__)
        l.debug('Calling restart on IrodsController')
        self.stop()
        self.wait_for_server_to_shutdown()
        self.start(write_to_stdout, test_mode)
        self.wait_for_server_to_start()

    def reload_configuration(self):
        """Send the SIGHUP signal to the server, causing it to reload the configuration."""
        l = logging.getLogger(__name__)
        server_pid = self.get_server_pid()
        if server_pid is None:
            l.info('iRODS server is not running')
            return
        os.kill(server_pid, signal.SIGHUP)
        # Give the server a chance to stop the listening socket opened by the original agent factory.
        time.sleep(1)
        self.wait_for_server_to_start()

    # TODO Consider removing this function. Admins should just use "ps".
    def status(self):
        l = logging.getLogger(__name__)
        l.debug('Calling status on IrodsController')
        self.config.clear_cache()
        server_proc = self.get_server_proc()
        if server_proc is None:
            l.info('No iRODS servers running.')
        else:
            l.info(format_binary_to_procs_dict(self.get_binary_to_procs_dict(server_proc)))

    # TODO Remove this function. Admins should use "ps".
    def get_binary_to_procs_dict(self, server_proc, server_descendants=None, binaries=None):
        if server_descendants is None and server_proc is not None and server_proc.is_running():
            try:
                server_descendants = server_proc.children(recursive=True)
            except psutil.NoSuchProcess:
                return None
        if server_descendants is None:
            server_descendants = []
        server_descendants = sorted(server_descendants, key=lambda _p: _p.pid)
        if binaries is None:
            binaries = self.server_binaries
        d = OrderedDict()
        for b in binaries:
            procs = list(filter(lambda _p: binary_matches(b, _p), server_descendants))
            if server_proc is not None and binary_matches(b, server_proc):
                procs.insert(0, server_proc)
            if procs:
                d[b] = procs
        return d

    def wait_for_server_to_start(self, retry_count=100):
        l = logging.getLogger(__name__)
        try_count = 1
        irods_port = int(self.config.server_config['zone_port'])

        for _ in range(retry_count):
            l.debug('Attempting to connect to iRODS server on port %s. Attempt #%s', irods_port, try_count)

            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                if s.connect_ex(('127.0.0.1', irods_port)) == 0:
                    l.debug('Successfully connected to port %s.', irods_port)
                    # Raise an exception if we were able to connect to the target port, but attempting
                    # to capturing the PID of the server returned nothing (i.e. the service account is
                    # not allowed to send signals to the server listening on the target port).
                    if self.get_server_pid() is None:
                        raise IrodsError('iRODS port is bound, but server is not started.')
                    s.send(b'\x00\x00\x00\x33<MsgHeader_PI><type>HEARTBEAT</type></MsgHeader_PI>')
                    message = s.recv(256)
                    if message == b'HEARTBEAT':
                        return
                    l.debug(f'iRODS port returned non-heartbeat message')

            try_count += 1
            time.sleep(1)

        raise IrodsError('iRODS server failed to start.')

    def wait_for_server_to_shutdown(self, retry_count=100):
        l = logging.getLogger(__name__)
        for _ in range(retry_count):
            l.debug('Waiting for iRODS server to shut down. Attempt #%s', try_count)
            if self.get_server_pid() is None:
                return
            time.sleep(1)
        raise IrodsError('iRODS server failed to shutdown.')

def binary_matches(binary_path, proc):
    if proc.is_running():
        try:
            if proc.exe():
                return os.path.samefile(binary_path, proc.exe())
            else:
                return os.path.basename(binary_path) == proc.name()
        except psutil.NoSuchProcess:
            return False

def capture_process_tree(server_proc, server_descendants, candidate_binaries=None):
    # define func to filter to candidate binaries
    if candidate_binaries:
        def should_return_proc(_p):
            for b in candidate_binaries:
                if binary_matches(b, _p):
                    return True
            return False
    else:
        def should_return_proc(_p):
            return True

    if server_proc.is_running():
        try:
            cur_descendants = set(filter(should_return_proc, server_proc.children(recursive=True)))
            orphaned_descendants = server_descendants.difference(cur_descendants)
            server_descendants.update(cur_descendants)
        except (psutil.NoSuchProcess):
            orphaned_descendants = server_descendants.copy()
    else:
        # if server isn't running any more, all previously known descendants are orphaned
        orphaned_descendants = server_descendants.copy()

    # get new descendants of orphans
    for orphaned_descendant in orphaned_descendants:
        if orphaned_descendant.is_running():
            try:
                server_descendants.update(filter(should_return_proc, orphaned_descendant.children(recursive=True)))
            except (psutil.NoSuchProcess):
                server_descendants.discard(orphaned_descendant)
        else:
            # remove descendants that are no longer running
            server_descendants.discard(orphaned_descendant)

    return server_proc.is_running() or server_descendants

def format_binary_to_procs_dict(proc_dict):
    text_list = []
    for binary, procs in proc_dict.items():
        text_list.append('{0} :\n{1}'.format(
            os.path.basename(binary),
            lib.indent(*['Process {0}'.format(proc.pid) for proc in procs])))
    return '\n'.join(text_list)
