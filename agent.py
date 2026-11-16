"""Listing Evidence: bounded, public-source exchange listing research."""
import concurrent.futures
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parent
PRIVATE = ROOT / 'private'
PRIVATE.mkdir(mode=0o700, exist_ok=True)
DB = PRIVATE / 'evidence.sqlite3'
SOURCES = {
    'coinbase_products': 'https://api.exchange.coinbase.com/products',
    'coinbase_currencies': 'https://api.exchange.coinbase.com/currencies',
    'kraken_pairs': 'https://api.kraken.com/0/public/AssetPairs',
    'kraken_assets': 'https://api.kraken.com/0/public/Assets',
}
LOCK = threading.Lock()
CACHE = {}
MAX_AGE = 300


def platform_secret():
    value = os.environ.get('AGENT_GAMES_HMAC_SECRET', '')
    if value:
        return value
    try:
        return json.loads((PRIVATE / 'platform-secret.json').read_text())['secret']
    except (FileNotFoundError, KeyError, ValueError):
        return ''


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def connect():
    db = sqlite3.connect(DB, timeout=15)
    db.execute('CREATE TABLE IF NOT EXISTS sources (sha TEXT PRIMARY KEY, url TEXT NOT NULL, fetched TEXT NOT NULL, body BLOB NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS tasks (task_id TEXT PRIMARY KEY, request_sha TEXT NOT NULL, response BLOB NOT NULL)')
    return db


def fetch_source(item):
    key, url = item
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'ListingEvidence/0.1', 'Accept': 'application/json'})
        with urllib.request.urlopen(request, timeout=12) as response:
            if response.url != url:
                raise ValueError('Unexpected source redirect')
            body = response.read(4_000_001)
            if len(body) > 4_000_000:
                raise ValueError('Source too large')
        data = json.loads(body)
        if key.startswith('kraken'):
            if not isinstance(data, dict) or data.get('error') != [] or not isinstance(data.get('result'), dict):
                raise ValueError('Invalid Kraken response')
        elif not isinstance(data, list) or not all(isinstance(x, dict) and isinstance(x.get('id'), str) for x in data):
            raise ValueError('Invalid Coinbase response')
        sha = hashlib.sha256(body).hexdigest()
        fetched = utc()
        with connect() as db:
            db.execute('INSERT OR IGNORE INTO sources VALUES (?,?,?,?)', (sha, url, fetched, body))
        return key, {'url': url, 'fetched_at': fetched, 'sha256': sha, 'available': True, 'data': data}
    except Exception:
        # Source failures are unknown, never evidence that an asset is absent.
        return key, {'url': url, 'fetched_at': utc(), 'available': False, 'error': 'Source could not be fetched or validated'}


def sources():
    with LOCK:
        if CACHE and time.monotonic() - CACHE['at'] < MAX_AGE:
            return CACHE['sources']
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            result = dict(pool.map(fetch_source, SOURCES.items()))
        CACHE.update(at=time.monotonic(), sources=result)
        return result


def normalize(query):
    symbol = str(query.get('symbol', '')).strip().upper()
    if not re.fullmatch(r'[A-Z0-9]{1,15}', symbol):
        raise ValueError('Use a ticker of 1 to 15 letters or numbers')
    contract = str(query.get('contract', '')).strip().lower()
    network = str(query.get('network', '')).strip().lower()
    if contract and not re.fullmatch(r'0x[0-9a-f]{40}', contract):
        raise ValueError('Optional contract must be a full EVM contract address')
    if contract and not network:
        raise ValueError('Specify the network when checking a contract')
    if network and not re.fullmatch(r'[a-z0-9_-]{1,30}', network):
        raise ValueError('Invalid network identifier')
    return symbol, contract, network


def analyze(query, src):
    symbol, contract, network = normalize(query)
    report = {
        'agent': 'Listing Evidence', 'version': '0.1.0', 'checked_at': utc(),
        'query': {'symbol': symbol, 'contract': contract or None, 'network': network or None},
        'scope': 'Public Coinbase Exchange and Kraken spot market feeds only. Other products, future listings and regional account access are outside this check.',
        'findings': [],
        'sources': [{k: v for k, v in s.items() if k != 'data'} for s in src.values()],
        'evidence_note': 'SHA-256 hashes identify captured source bytes. They do not prove source authenticity, truth, or a zero-knowledge verification. No zkVerify proof is submitted.',
    }
    for exchange, feed in [('Coinbase Exchange', 'coinbase_products'), ('Kraken', 'kraken_pairs')]:
        result = {'exchange': exchange, 'symbol': symbol, 'identity': 'unverified', 'markets': []}
        source = src[feed]
        if not source['available']:
            result.update(status='unknown', explanation='The market feed could not be checked. No listing conclusion is available.')
            report['findings'].append(result)
            continue
        data = source['data']
        if feed == 'coinbase_products':
            matches = [x for x in data if x.get('base_currency') == symbol]
            result['markets'] = [{'pair': x['id'], 'status': x.get('status', 'unknown'), 'trading_disabled': x.get('trading_disabled', True), 'cancel_only': x.get('cancel_only', False), 'limit_only': x.get('limit_only', False), 'post_only': x.get('post_only', False)} for x in matches]
            assets = src['coinbase_currencies']
            candidates = [x for x in assets.get('data', []) if x.get('id') == symbol] if assets['available'] else []
            result['candidate_names'] = [x.get('name', '') for x in candidates]
            if contract:
                if not assets['available']:
                    result['identity'] = 'unknown'
                else:
                    result['identity'] = 'contract_match' if any(n.get('id', '').lower() == network and n.get('contract_address', '').lower() == contract for x in candidates for n in x.get('supported_networks', [])) else 'no_contract_match'
            tradable = [x for x in matches if x.get('status') == 'online' and x.get('trading_disabled') is False and not x.get('cancel_only', False)]
        else:
            assets = src['kraken_assets']
            alias = {'BTC': 'XBT', 'DOGE': 'XDG'}.get(symbol, symbol)
            matching_assets = {k for k, v in assets.get('data', {}).get('result', {}).items() if v.get('altname') == alias} if assets['available'] else set()
            result['symbol_alias'] = alias
            if not assets['available']:
                result.update(status='unknown', explanation='The asset identity feed is unavailable, so market symbols cannot be resolved reliably.')
                report['findings'].append(result)
                continue
            matches = [dict(x, pair=k) for k, x in data['result'].items() if x.get('base') in matching_assets]
            result['markets'] = [{'pair': x.get('wsname') or x['pair'], 'status': x.get('status', 'unknown')} for x in matches]
            tradable = [x for x in matches if x.get('status') == 'online']
            if contract:
                result['identity'] = 'unknown'
        if contract and result['identity'] != 'contract_match':
            result.update(status='identity_unconfirmed', explanation='This contract on this network is not confirmed by these feeds. Ticker matches do not establish token identity.')
        elif tradable:
            result.update(status='market_observed', explanation='An online spot market was observed for this symbol. Identity remains unverified unless an exact contract match is shown; individual account eligibility is not checked.')
        elif matches:
            result.update(status='market_restricted_or_offline', explanation='The symbol appears in the market feed, but no online market meeting the trading checks was observed.')
        else:
            result.update(status='not_observed', explanation='No exact base-asset match was observed in this spot feed. This does not establish that the asset is unavailable in every exchange product.')
        report['findings'].append(result)
    report['next_step'] = 'Verify the exact asset identity and exchange announcement before acting. A price-tracking page is not proof of a tradable listing.'
    return report


def run(query):
    return analyze(query, sources())


def signed_task(raw, signature, secret):
    if not secret:
        raise PermissionError('Agent Games secret is not configured')
    expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    supplied = signature.removeprefix('sha256=')
    if not hmac.compare_digest(expected, supplied):
        raise PermissionError('Invalid task signature')
    envelope = json.loads(raw)
    issued = envelope.get('issued_at', envelope.get('issuedAt', ''))
    try:
        timestamp = dt.datetime.fromisoformat(issued.replace('Z', '+00:00'))
        age = (dt.datetime.now(dt.timezone.utc) - timestamp).total_seconds()
    except (ValueError, TypeError):
        raise ValueError('A valid issued_at timestamp is required')
    if not -30 <= age <= 300:
        raise ValueError('Expired task')
    if envelope.get('type') == 'agent-games.preflight.v1':
        return {'ok': True, 'protocolVersion': 'v1'}
    if envelope.get('type') != 'listing-evidence.research.v1':
        raise ValueError('Unsupported task type: this build is for Wildcard, not the scored gameplay tracks')
    deadline = envelope.get('deadline_at')
    if deadline and dt.datetime.fromisoformat(deadline.replace('Z', '+00:00')) <= dt.datetime.now(dt.timezone.utc):
        raise ValueError('Expired deadline')
    task_id = str(envelope.get('task_id', ''))
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,100}', task_id):
        raise ValueError('A task_id is required')
    sha = hashlib.sha256(raw).hexdigest()
    with LOCK:
        with connect() as db:
            found = db.execute('SELECT request_sha,response FROM tasks WHERE task_id=?', (task_id,)).fetchone()
    if found:
        if found[0] != sha:
            raise ValueError('Task ID reused with different input')
        return json.loads(found[1])
    result = run(envelope.get('input', {}))
    with LOCK:
        with connect() as db:
            db.execute('INSERT OR IGNORE INTO tasks VALUES (?,?,?)', (task_id, sha, json.dumps(result)))
            stored = db.execute('SELECT request_sha,response FROM tasks WHERE task_id=?', (task_id,)).fetchone()
    if stored[0] != sha:
        raise ValueError('Task ID reused with different input')
    return json.loads(stored[1])
