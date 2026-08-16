#!/usr/bin/env python3
"""Metadata-only authorization inspection and rollback revocation."""
from __future__ import annotations

import argparse
import json
import time
import sqlite3
from pathlib import Path

from .authorization import AuthorizationError,SQLiteAuthorizationStore


def main(argv: list[str]|None=None) -> int:
    parser=argparse.ArgumentParser(description="Inspect or revoke Semantic Gate authorization metadata")
    sub=parser.add_subparsers(dest="command",required=True)
    listing=sub.add_parser("list",help="List metadata without bearer tokens")
    listing.add_argument("--database",required=True); listing.add_argument("--state",action="append",choices=["issued","executing","executed","failed","simulated","unknown","cancelled","expired"])
    revoke=sub.add_parser("revoke-issued",help="Revoke every unconsumed issued authorization for rollback")
    revoke.add_argument("--database",required=True); revoke.add_argument("--actor",required=True)
    recover=sub.add_parser("recover-interrupted",help="Mark one operator-confirmed abandoned execution unknown")
    recover.add_argument("--database",required=True); recover.add_argument("--authorization-id",required=True); recover.add_argument("--actor",required=True)
    reconcile=sub.add_parser("reconcile",help="Record a verified downstream outcome for one unknown authorization")
    reconcile.add_argument("--database",required=True); reconcile.add_argument("--authorization-id",required=True); reconcile.add_argument("--actor",required=True); reconcile.add_argument("--outcome",required=True,choices=["executed","failed"]); reconcile.add_argument("--receipt-file",required=True)
    args=parser.parse_args(argv); database=Path(args.database)
    if not database.is_file(): parser.error("authorization database does not exist")
    try:
        with sqlite3.connect(f"file:{database}?mode=ro",uri=True) as check:
            columns={row[1] for row in check.execute("PRAGMA table_info(authorizations)")}
        required={"authorization_id","request_id","state","token_json","request_snapshot_json"}
        if not required<=columns: parser.error("database is not a Semantic Gate authorization store")
    except sqlite3.Error as error: parser.error(f"authorization database is invalid: {error}")
    store=SQLiteAuthorizationStore(database)
    try:
        if args.command=="list": result={"authorizations":store.list_metadata(set(args.state) if args.state else None)}
        elif args.command=="revoke-issued": result={"revoked":store.revoke_all_issued(actor=args.actor,now=int(time.time()))}
        elif args.command=="recover-interrupted": result=store.recover_interrupted(args.authorization_id,actor=args.actor,now=int(time.time()))
        else:
            receipt=json.loads(Path(args.receipt_file).read_text())
            if not isinstance(receipt,dict): raise AuthorizationError("receipt file must contain a JSON object")
            result=store.reconcile(args.authorization_id,outcome=args.outcome,actor=args.actor,receipt=receipt,now=int(time.time()))
        if isinstance(result,dict) and "token" in result: result={key:value for key,value in result.items() if key!="token"}
    except (AuthorizationError,OSError,json.JSONDecodeError) as error:
        parser.error(str(error))
    finally: store.close()
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    return 0


if __name__=="__main__": raise SystemExit(main())
