import copy
import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import agent


def fixture():
    return {
        'coinbase_products': {'url': 'https://api.exchange.coinbase.com/products', 'available': True, 'data': [{'id': 'PAX-USD', 'base_currency': 'PAX', 'status': 'online', 'trading_disabled': False}]},
        'coinbase_currencies': {'url': 'https://api.exchange.coinbase.com/currencies', 'available': True, 'data': [{'id': 'PAX', 'name': 'Unrelated asset', 'supported_networks': [{'id': 'ethereum', 'contract_address': '0x'+'1'*40}]}]},
        'kraken_assets': {'url': 'https://api.kraken.com/0/public/Assets', 'available': True, 'data': {'result': {'XXBT': {'altname': 'XBT'}}}},
        'kraken_pairs': {'url': 'https://api.kraken.com/0/public/AssetPairs', 'available': True, 'data': {'result': {'XXBTZUSD': {'base': 'XXBT', 'wsname': 'XBT/USD', 'status': 'online'}}}},
    }


class PolicyTests(unittest.TestCase):
    def test_ticker_collision_does_not_confirm_contract(self):
        d = agent.analyze({'symbol': 'PAX', 'network': 'ethereum', 'contract': '0x'+'2'*40}, fixture())
        self.assertEqual(d['findings'][0]['status'], 'identity_unconfirmed')
        self.assertEqual(d['findings'][0]['identity'], 'no_contract_match')

    def test_source_failure_is_unknown_not_absence(self):
        src = fixture();src['coinbase_products'] = {'url': 'x', 'available': False}
        self.assertEqual(agent.analyze({'symbol': 'WPAX'}, src)['findings'][0]['status'], 'unknown')

    def test_cancel_only_is_not_reported_as_online_market(self):
        src = fixture();src['coinbase_products']['data'][0]['cancel_only'] = True
        self.assertEqual(agent.analyze({'symbol': 'PAX'}, src)['findings'][0]['status'], 'market_restricted_or_offline')

    def test_kraken_btc_alias_and_identity_limit(self):
        r = agent.analyze({'symbol': 'BTC'}, fixture())['findings'][1]
        self.assertEqual(r['status'], 'market_observed')
        self.assertEqual(r['identity'], 'unverified')

    def test_contract_requires_network_and_exact_chain(self):
        with self.assertRaises(ValueError):agent.normalize({'symbol': 'PAX', 'contract': '0x'+'1'*40})
        d = agent.analyze({'symbol': 'PAX', 'network': 'base', 'contract': '0x'+'1'*40}, fixture())
        self.assertEqual(d['findings'][0]['identity'], 'no_contract_match')

    def test_unrelated_symbol_has_bounded_negative(self):
        r = agent.analyze({'symbol': 'WPAX'}, fixture())['findings'][0]
        self.assertEqual(r['status'], 'not_observed')
        self.assertIn('does not establish', r['explanation'])

    def test_preflight_authentication_and_expiry(self):
        raw = json.dumps({'type': 'agent-games.preflight.v1', 'issued_at': agent.utc()}).encode()
        sig = hmac.new(b'test-secret', raw, hashlib.sha256).hexdigest()
        self.assertEqual(agent.signed_task(raw, sig, 'test-secret'), {'ok': True, 'protocolVersion': 'v1'})
        with self.assertRaises(PermissionError):agent.signed_task(raw, 'bad', 'test-secret')
        old = json.dumps({'type': 'agent-games.preflight.v1', 'issued_at': '2020-01-01T00:00:00Z'}).encode()
        with self.assertRaises(ValueError):agent.signed_task(old, hmac.new(b'test-secret', old, hashlib.sha256).hexdigest(), 'test-secret')

    def test_task_replay_returns_original_and_conflict_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(agent, 'DB', Path(tmp)/'test.sqlite3'), patch.object(agent, 'sources', return_value=fixture()) as fetch:
            env={'type':'listing-evidence.research.v1', 'task_id':'same-task', 'issued_at':agent.utc(), 'input':{'symbol':'BTC'}}
            def call(e):
                raw=json.dumps(e).encode();return agent.signed_task(raw,hmac.new(b'test',raw,hashlib.sha256).hexdigest(),'test')
            first=call(env);second=call(env)
            self.assertEqual(first,second);self.assertEqual(fetch.call_count,1)
            env['input']['symbol']='WPAX'
            with self.assertRaises(ValueError):call(env)


if __name__ == '__main__':unittest.main()
