#region Copyright
// Copyright (c) 2020 TonesNotes
// Distributed under the Open BSV software license, see the accompanying file LICENSE.
#endregion
using System.Collections.Generic;

namespace KzBsv
{
	public class KzBScriptPubMultisig : KzBScript
	{
		public KzBScriptPubMultisig(int required, List<KzPubKey> pubKey)
		{
			IsPub = true;
			_TemplateId = KzScriptTemplateId.OpCheckMultisig;
			this.Add((KzOpcode)(required + (int)KzOpcode.OP_1 - 1));
			for (int i = 0; i < pubKey.Count; i++)
			{
				this.Push(pubKey[i].Span);
			}

			this.Add((KzOpcode)(pubKey.Count + (int)KzOpcode.OP_1 - 1))
				 .Add(KzOpcode.OP_CHECKMULTISIG)
			 ;
		}
	}

	public class KzBScriptSigMultisig : KzBScript
	{
		public KzBScriptSigMultisig(int required)
		{
			IsPub = false;
			_TemplateId = KzScriptTemplateId.OpCheckMultisig;
			this.Push(new byte[] { 0 });
			for (int i = 0; i < required; i++)
			{
				this.Push(new byte[72]); // This will become the CHECKSIG signature
			}
		}
	}
}
