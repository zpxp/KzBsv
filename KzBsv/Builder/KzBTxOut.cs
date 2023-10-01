#region Copyright
// Copyright (c) 2020 TonesNotes
// Distributed under the Open BSV software license, see the accompanying file LICENSE.
#endregion
using System.Collections.Generic;

namespace KzBsv
{
	public class KzBTxOut
	{
		public KzAmount Value;
		public KzBScript ScriptPub = new KzBScript();

		public KzPubKey PubKey;

		public KzBTxOut() { }

		public KzBTxOut(KzTxOut txOut)
		{
			Value = txOut.Value;
			ScriptPub.Set(txOut.ScriptPub);
		}


		public KzBTxOut(KzAmount satoshis, KzBScript scriptPub)
		{
			Value = satoshis;
			ScriptPub.Set(scriptPub);
		}

		public static KzBTxOut ToP2PKH(KzPubKey pubKey, KzAmount value)
		{
			var pub = KzBScript.NewPubP2PKH(pubKey.ToHash160());

			var r = new KzBTxOut
			{
				Value = value,
				ScriptPub = pub,
				PubKey = pubKey
			};
			return r;
		}

		public static KzBTxOut ToP2PKH(string address, KzAmount value)
		{
			var hash160 = KzEncoders.B58Check.Decode(address)[1..];
			var pub = KzBScript.NewPubP2PKH(new KzUInt160(hash160));
			var r = new KzBTxOut
			{
				Value = value,
				ScriptPub = pub,
			};
			return r;
		}

		public static KzBTxOut ToMultisig(int required, List<KzPubKey> pubKeys, KzAmount value)
		{
			var pub = KzBScript.NewPubMultisig(required, pubKeys);

			var r = new KzBTxOut
			{
				Value = value,
				ScriptPub = pub,
			};
			return r;
		}

		public KzTxOut ToTxOut()
		{
			return new KzTxOut(Value, ScriptPub);
		}
	}


}
