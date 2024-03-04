#region Copyright
// Copyright (c) 2020 TonesNotes
// Distributed under the Open BSV software license, see the accompanying file LICENSE.
#endregion
using System;
using System.Linq;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.ComponentModel;

namespace KzBsv
{

	/// <summary>
	/// Support dynamic construction of new Bitcoin transactions.
	/// See <see cref="KzTransaction"/> for serializing and sending.
	/// </summary>
	public class KzBTransaction
	{
		public Int32 Version = 1;
		public List<KzBTxIn> Vin = new List<KzBTxIn>();
		public List<KzBTxOut> Vout = new List<KzBTxOut>();
		public UInt32 LockTime = 0;

		public KzUInt256? HashTx;

		public KzAmount? CurrentFee => Vin.Where(i => i.PrevOut.N >= 0).Sum(i => i.Value) - Vout.Sum(o => o.Value);

		public KzBTransaction() { }

		public KzBTransaction(KzTransaction tx)
		{
			Version = tx.Version;
			Vin = tx.Vin.Select(x => new KzBTxIn(x)).ToList();
			Vout = tx.Vout.Select(x => new KzBTxOut(x)).ToList();
			LockTime = tx.LockTime;
			HashTx = tx.HashTx;
			if (HashTx.Value == KzUInt256.Zero) HashTx = null;
		}

		public static KzBTransaction P2PKH
			 (IEnumerable<(KzPubKey pubKey, long value, byte[] hashTxBytes, int n, byte[] scriptPub)> from
			 , IEnumerable<(KzPubKey pubKey, long value)> to
			 )
		{
			var r = new KzBTransaction();
			foreach (var i in from) r.AddInP2PKH(i.pubKey, i.value, i.hashTxBytes.ToKzUInt256(), i.n, new KzScript(i.scriptPub));
			foreach (var o in to) r.AddOutP2PKH(o.pubKey, o.value);
			return r;
		}

		public KzAmount EstimateFeeInSatoshis()
		{
			var size = ToTransaction().ToBytes().Length;
			return new KzAmount((long)(Kz.Params.FeeSatsPerByte * size));
		}

		public KzAmount EstimateFeeInSatoshis(double feeSatsPerByte)
		{
			var size = ToTransaction().ToBytes().Length;
			return new KzAmount((long)Math.Max(1, feeSatsPerByte * size));
		}

		public KzAmount SafeEstimateFeeInSatoshis(double feeSatsPerByte)
		{
			var size = ToTransaction().ToBytes().Length;
			return new KzAmount((long)Math.Ceiling(feeSatsPerByte * size));
		}

		public void AddInP2PKH(KzPubKey pubKey, KzAmount value, KzUInt256 txId, int n, KzScript scriptPub, UInt32 sequence = KzTxIn.SEQUENCE_FINAL)
		{
			Vin.Add(KzBTxIn.FromP2PKH(pubKey, value, txId, n, scriptPub, sequence));
		}

		public void AddInMultisig(int required, List<KzPubKey> pubKeys, KzAmount value, KzUInt256 txId, int n, KzScript scriptPub, UInt32 sequence = KzTxIn.SEQUENCE_FINAL)
		{
			Vin.Add(KzBTxIn.FromMultisig(required, pubKeys, value, txId, n, scriptPub, sequence));
		}

		public static KzBTransaction P2PKH(IEnumerable<(KzPubKey pubKey, KzTransaction tx, int n)> from, IEnumerable<(KzPubKey pubKey, long value)> to)
		{
			var r = new KzBTransaction();
			foreach (var i in from) r.AddInP2PKH(i.pubKey, i.tx, i.n);
			foreach (var o in to) r.AddOutP2PKH(o.pubKey, o.value);
			return r;
		}

		public void AddInP2PKH(KzPubKey pubKey, KzTransaction tx, int n, UInt32 sequence = KzTxIn.SEQUENCE_FINAL)
		{
			Vin.Add(KzBTxIn.FromP2PKH(pubKey, tx, n, sequence));
		}

		public void AddIn((KzTransaction tx, KzTxOut o, int i) txOut)
		{
			throw new NotImplementedException();
		}

		public void AddIn(KzTxIn txIn)
		{
			Vin.Add(new KzBTxIn(txIn));
		}

		public void AddIn(KzOutPoint prevout, KzScript scriptSig, UInt32 sequence = KzTxIn.SEQUENCE_FINAL)
		{
			throw new NotImplementedException();
			//Vin.Add(new KzTxInBuilder { Prevout = prevout, ScriptSig., sequence));
		}

		public void AddOutP2PKH(KzPubKey pubKey, KzAmount value)
		{
			Vout.Add(KzBTxOut.ToP2PKH(pubKey, value));
		}

		public void AddOutMultisig(int required, List<KzPubKey> pubKeys, KzAmount value)
		{
			Vout.Add(KzBTxOut.ToMultisig(required, pubKeys, value));
		}

		public void AddOut(KzScript scriptPubKey, long nValue)
		{
			Vout.Add(new KzBTxOut(new KzTxOut(nValue, scriptPubKey)));
		}

		public KzTransaction ToTransaction() => new KzTransaction(this);

		public string ToHex() => ToTransaction().ToBytes().ToHex();

		public ReadOnlySequence<byte> ToReadOnlySequence()
		{
			throw new NotImplementedException();
			//return new ReadOnlySequence<byte>();
		}

		public ReadOnlySequence<byte> ToSequence()
		{
			throw new NotImplementedException();
			//return new ReadOnlySequence<byte>();
		}

		/// <summary>
		/// Find all the OP_RETURN outputs followed by a matching protocol identifier pushdata (20 bytes long).
		/// For each match, return the KzBTxOut and a trimmed array the remaining ScriptPub KzBOp's.
		/// </summary>
		/// <param name="protocol"></param>
		/// <returns></returns>
		public IEnumerable<(KzBTxOut o, KzBOp[] data)> FindPushDataByProtocol(KzUInt160 protocol)
		{
			var val = protocol.ToBytes();

			foreach (var o in Vout)
			{
				var ops = o.ScriptPub.Ops;
				if (ops.Count > 2
					 && ops[0].Op.Code == KzOpcode.OP_RETURN
					 && ops[1].Op.Code == KzOpcode.OP_PUSH20
					 && ops[1].Op.Data.Sequence.CompareTo(val) == 0)
					yield return (o, ops.Skip(2).ToArray());
			}
		}

		public bool CheckSignatures(IEnumerable<KzPrivKey> privKeys = null)
		{
			return Sign(privKeys, confirmExistingSignatures: true);
		}

		/// <summary>
		/// Add signature to input at given index. Assumes the sig is valid.
		/// </summary>
		public bool AddSignature(int inputIndex, byte[] sig)
		{
			var input = Vin[inputIndex];
			var scriptSig = input.ScriptSig;
			if (scriptSig.Ops.Count == 2)
			{
				if (scriptSig.TemplateId == KzScriptTemplateId.P2PKH || scriptSig.TemplateId == KzScriptTemplateId.Unknown)
				{
					var pubKey = new KzPubKey();
					pubKey.Set(scriptSig.Ops[1].Op.Data.ToSpan());
					if (pubKey.IsValid)
					{
						if (input.ScriptPub == null)
						{
							input.ScriptPub = new KzBScriptPubP2PKH(pubKey.ToHash160());
						}
						var op = KzOp.Push(sig.AsSpan());
						scriptSig.Ops[0] = op;
						return true;
					}
				}
			}
			return false;
		}

		public bool IsFullySigned()
		{
			foreach (var input in Vin)
			{
				var scriptSig = input.ScriptSig;
				if (scriptSig.Ops.Count == 2)
				{
					if (scriptSig.TemplateId == KzScriptTemplateId.P2PKH || scriptSig.TemplateId == KzScriptTemplateId.Unknown)
					{
						if (scriptSig.Ops[0].Op.Data.Sequence.IsEmpty())
						{
							// not signed
							return false;
						}
					}
					else if (scriptSig.TemplateId == KzScriptTemplateId.OpCheckMultisig)
					{
						if (input.ScriptPub == null)
						{
							throw new Exception("Multisig input ScriptPub null");
						}
						var required = scriptSig.Ops.Count - 1;
						// skip the first op its a blank op
						foreach (var op in scriptSig.Ops.Skip(1))
						{
							if (op.Op.Data.Sequence.IsEmpty())
							{
								// not signed
								return false;
							}
						}
					}
				}
			}
			return true;
		}

		public bool Sign(IEnumerable<KzPrivKey> privKeys, bool confirmExistingSignatures = false)
		{
			return Sign(privKeys.ToList(), null, confirmExistingSignatures);
		}

		public bool Sign(IEnumerable<KzBSignature> signatures, bool confirmExistingSignatures = false)
		{
			return Sign(null, signatures.ToList(), confirmExistingSignatures);
		}

		public bool Sign(IEnumerable<KzPrivKey> privKeys, IEnumerable<KzBSignature> signatures)
		{
			return Sign(privKeys.ToList(), signatures.ToList(), false);
		}

		public bool Sign(List<KzPrivKey> privKeys, List<KzBSignature> signatures, bool confirmExistingSignatures = false)
		{
			var signedOk = true;
			var sigHashType = new KzSigHashType(KzSigHash.ALL | KzSigHash.FORKID);
			var tx = ToTransaction();
			var nIn = -1;
			foreach (var input in Vin)
			{
				nIn++;
				var scriptSig = input.ScriptSig;
				if (scriptSig.Ops.Count == 2)
				{
					if (scriptSig.TemplateId == KzScriptTemplateId.P2PKH || scriptSig.TemplateId == KzScriptTemplateId.Unknown)
					{
						if (!scriptSig.Ops[0].Op.Data.Sequence.IsEmpty())
						{
							// already signed
							continue;
						}
						var pubKey = new KzPubKey();
						pubKey.Set(scriptSig.Ops[1].Op.Data.ToSpan());
						if (pubKey.IsValid)
						{
							if (signatures != null &&
								signatures.FirstOrDefault(x => x.OutputIdx == input.PrevOutN && x.HashTx == input.PrevOutHashTx) is var customSig &&
								customSig != null)
							{
								// insert custom sig
								var op = KzOp.Push(customSig.Signature.AsSpan());
								if (confirmExistingSignatures)
								{
									signedOk &= op == scriptSig.Ops[0].Op;
								}
								else
								{
									scriptSig.Ops[0] = op;
								}
								continue;
							}
							var privKey = input.PrivKey ?? privKeys?.FirstOrDefault(k => k.GetPubKey() == pubKey);
							if (privKey != null)
							{
								if (input.ScriptPub == null)
								{
									input.ScriptPub = new KzBScriptPubP2PKH(pubKey.ToHash160());
								}
								var value = input.Value ?? input.PrevOutTx?.Vout[input.PrevOutN].Value ?? 0L;
								var sigHash = KzScriptInterpreter.ComputeSignatureHash(input.ScriptPub, tx, nIn, sigHashType, value, KzScriptFlags.ENABLE_SIGHASH_FORKID);
								var (ok, sig) = privKey.Sign(sigHash);
								if (ok)
								{
									var sigWithType = new byte[sig.Length + 1];
									sig.CopyTo(sigWithType.AsSpan());
									sigWithType[^1] = (byte)sigHashType.rawSigHashType;
									var op = KzOp.Push(sigWithType.AsSpan());
									if (confirmExistingSignatures)
									{
										signedOk &= op == scriptSig.Ops[0].Op;
									}
									else
									{
										scriptSig.Ops[0] = op;
									}
								}
								else { signedOk = false; }
							}
							else if (scriptSig.Ops[0].Op.Data.Length == 0)
							{
								signedOk = false;
							}
						}
						else { signedOk = false; }
					}
					else if (scriptSig.TemplateId == KzScriptTemplateId.OpCheckMultisig)
					{
						if (input.ScriptPub == null)
						{
							throw new Exception("Multisig input ScriptPub null");
						}
						var required = scriptSig.Ops.Count - 1;
						var keys = input.ScriptPub.GetMultisigKeys();
						var value = input.Value ?? input.PrevOutTx?.Vout[input.PrevOutN].Value ?? 0L;
						var insertIdx = 1;
						if (signatures != null)
						{
							foreach (var customSig in signatures.Where(x => x.OutputIdx == input.PrevOutN && x.HashTx == input.PrevOutHashTx))
							{
								if (insertIdx >= scriptSig.Ops.Count)
								{
									break;
								}
								// insert custom sig
								var op = KzOp.Push(customSig.Signature.AsSpan());
								if (confirmExistingSignatures)
								{
									signedOk &= op == scriptSig.Ops[insertIdx++].Op;
								}
								else
								{
									scriptSig.Ops[insertIdx++] = op;
								}
							}
						}

						foreach (var privKey in privKeys)
						{
							if (required == 0)
							{
								break;
							}
							if (insertIdx >= scriptSig.Ops.Count)
							{
								break;
							}
							var incPub = privKey.GetPubKey();
							// see if this key can sign
							var pub = keys.FirstOrDefault(x => x.ReadOnlySpan.CompareTo(incPub.ReadOnlySpan.ToSequence()) == 0);
							if (pub != null)
							{
								var sigHash = KzScriptInterpreter.ComputeSignatureHash(input.ScriptPub, tx, nIn, sigHashType, value, KzScriptFlags.ENABLE_SIGHASH_FORKID);
								var (ok, sig) = privKey.Sign(sigHash);
								if (ok)
								{
									--required;
									var sigWithType = new byte[sig.Length + 1];
									sig.CopyTo(sigWithType.AsSpan());
									sigWithType[^1] = (byte)sigHashType.rawSigHashType;
									var op = KzOp.Push(sigWithType.AsSpan());
									if (confirmExistingSignatures)
									{
										signedOk &= op == scriptSig.Ops[insertIdx++].Op;
									}
									else
									{
										scriptSig.Ops[insertIdx++] = op;
									}
								}
								else { signedOk = false; }
							}
						}

					}

				}
			}
			return signedOk;
#if false
            var tx = txb.ToTransaction();
                var bytes = tx.ToBytes();
                var hex = bytes.ToHex();

                var (ok, sig) = privKey1h11.Sign(sigHash);
            //var (ok, sig) = privKey1h11.SignCompact(sigHash);
            if (ok) {
                var sigWithType = new byte[sig.Length + 1];
                sig.CopyTo(sigWithType.AsSpan());
                sigWithType[^1] = (byte)sigHashType.rawSigHashType;
                txb.Vin[0].ScriptSig.Ops[0] = KzOp.Push(sigWithType.AsSpan());
            }
#endif
		}
	}


}
