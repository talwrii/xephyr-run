import os
import re
import tempfile
import unittest
from pathlib import Path

from xephyr_run import cli, connect_filter, registry


class Size(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(cli.parse_size('640x400'), '640x400')
        for bad in ('', '640', 'axb', '640x400+1+1'):
            with self.assertRaises(ValueError):
                cli.parse_size(bad)


class Display(unittest.TestCase):
    def test_skips_taken_numbers(self):
        with tempfile.TemporaryDirectory() as directory:
            sockets = Path(directory)
            self.assertEqual(cli.free_display(sockets, first=5), 5)
            (sockets/'X5').touch()
            (sockets/'X6').touch()
            self.assertEqual(cli.free_display(sockets, first=5), 7)


class Confinement(unittest.TestCase):
    def policy_for(self, number):
        with tempfile.TemporaryDirectory() as directory:
            sockets = Path(directory)/'.X11-unix'
            sockets.mkdir()
            return connect_filter.rules_policy(cli.confine_rules(number, sockets)), os.path.realpath(sockets)

    def test_only_the_own_display_and_non_x_sockets_are_allowed(self):
        policy, base = self.policy_for(90)
        unix = lambda name: connect_filter.Address(1, name, b'')
        self.assertTrue(policy(unix(f'{base}/X90')))
        self.assertFalse(policy(unix(f'{base}/X0')))
        self.assertFalse(policy(unix(f'{base}/X900')))
        self.assertFalse(policy(unix('@/tmp/.X11-unix/X0')))
        self.assertFalse(policy(unix('@anything')))
        self.assertTrue(policy(unix('/run/user/1000/bus')))


class Registry(unittest.TestCase):
    def record(self, name, server_pid=None):
        return {'name': name, 'display': ':90', 'server_pid': server_pid or os.getpid(),
                'pid': os.getpid(), 'command': ['xclock'], 'started': 0}

    def test_round_trip_and_listing(self):
        with tempfile.TemporaryDirectory() as directory:
            where = Path(directory)/'state'
            self.assertEqual(registry.records(where), [])
            registry.save(self.record('b'), where)
            registry.save(self.record('a'), where)
            self.assertEqual([r['name'] for r in registry.records(where)], ['a', 'b'])
            registry.remove('a', where)
            self.assertIsNone(registry.load('a', where))
            self.assertEqual(registry.load('b', where)['display'], ':90')

    def test_stale_record_is_pruned(self):
        with tempfile.TemporaryDirectory() as directory:
            where = Path(directory)
            registry.save(self.record('gone', server_pid=2**22 + 12345), where)
            self.assertIsNone(registry.load('gone', where))
            self.assertFalse((where/'gone.json').exists())

    def test_rejects_unsafe_names(self):
        for bad in ('', '../x', 'a b', 'a/b'):
            with self.assertRaises(ValueError):
                registry.validate_name(bad)


if __name__ == '__main__':
    unittest.main()
