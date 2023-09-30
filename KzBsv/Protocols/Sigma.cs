using Secp256k1Net;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace KzBsv
{



	public class AuthToken
	{
		public string Type { get; set; }
		public string Value { get; set; }
		public string Key { get; set; }
	}


	public class Sig
	{
		public string Address { get; set; }
		public KzBScript SigmaScript { get; set; }
		public KzBTransaction SignedTx { get; set; }
		public string Signature { get; set; }
		public string Algorithm { get; set; }
		public int Vin { get; set; }
		public int TargetVout { get; set; }
	}

	public class Sigma
	{
		private KzUInt256 _inputHash = KzUInt256.Zero;
		private KzUInt256 _dataHash = KzUInt256.Zero;
		private KzBTransaction _transaction;
		private int _sigmaInstance;
		private int _refVin;
		private int _targetVout;
		private Sig _sig = null;

		private const string SigmaHex = "5349474d41";

		public KzBTransaction Transaction => _transaction;

		public Sigma(
			 KzTransaction transaction,
			 int targetVout = 0,
			 int sigmaInstance = 0,
			 int refVin = 0)
			 :this(new KzBTransaction(transaction), targetVout, sigmaInstance, refVin)
		{
		}

		public Sigma(
			 KzBTransaction transaction,
			 int targetVout = 0,
			 int sigmaInstance = 0,
			 int refVin = 0)
		{
			_transaction = transaction;
			_targetVout = targetVout;
			_refVin = refVin;
			_sigmaInstance = sigmaInstance;
			_sig = Sig;
			SetHashes();
		}

		public void SetHashes()
		{
			_inputHash = GetInputHash();
			_dataHash = GetDataHash();
		}

		public void SetTargetVout(int targetVout)
		{
			_targetVout = targetVout;
		}

		public void SetSigmaInstance(int sigmaInstance)
		{
			_sigmaInstance = sigmaInstance;
		}

		public KzUInt256 GetMessageHash()
		{
			if (_inputHash == KzUInt256.Zero || _dataHash == KzUInt256.Zero)
			{
				throw new Exception("Input hash and data hash must be set");
			}

			using var hasher = new KzWriterHash();
			hasher.Add(_inputHash).Add(_dataHash);
			return hasher.GetHashFinal();
		}

		public KzBTransaction GetTransaction()
		{
			return _transaction;
		}

		private Sig Sign(ReadOnlySpan<byte> signature, string address)
		{
			var vin = _refVin == -1 ? _targetVout : _refVin;
			var script = new KzBScript()
				.Add(SigmaHex.HexToBytes())
				.Add(Encoding.UTF8.GetBytes("BSM"))
				.Add(Encoding.UTF8.GetBytes(address))
				.Add(signature.ToArray())
				.Add(new KzBOp(new KzValType(Encoding.UTF8.GetBytes(vin.ToString()))));


			_sig = new Sig
			{
				Algorithm = "BSM",
				Address = address,
				Signature = Convert.ToBase64String(signature),
				Vin = vin,
				TargetVout = _targetVout,
			};

			var existingAsm = TargetTxOut.ScriptPub.Ops;
			var containsOpReturn = existingAsm.Any(x => x.Op.Code == KzOpcode.OP_RETURN);
			var separator = containsOpReturn ? new KzBOp(KzOp.Push("7c".HexToBytes())) : new KzBOp(new KzOp(KzOpcode.OP_RETURN));

			var newScriptAsm = new List<KzBOp>();

			var existingSig = _sig;

			if (existingSig != null && _sigmaInstance == GetSigInstanceCount())
			{
				var sigIndex = GetSigInstancePosition();

				var newSignedAsmChunks = script.Ops;
				if (sigIndex != -1)
				{
					existingAsm = existingAsm.Take(sigIndex)
						.Concat(newSignedAsmChunks)
						.Concat(existingAsm.Skip(sigIndex + 5)).ToList();
				}
			}

			// Append the new signature
			newScriptAsm = existingAsm.Append(separator).Concat(script.Ops).ToList();

			var newScript = KzBScript.FromAsmString(newScriptAsm);
			var signedTx = new KzBTransaction(_transaction.ToTransaction());
			var signedTxOut = new KzBTxOut(TargetTxOut.Value, newScript);
			signedTx.Vout[_targetVout] = signedTxOut;

			_transaction = signedTx;

			return new Sig
			{
				SigmaScript = script,
				SignedTx = signedTx,
				Address = address,
				Signature = Convert.ToBase64String(signature),
				Algorithm = "BSM",
				Vin = vin,
				TargetVout = _targetVout,
			};
		}

		public Sig Sign(KzPrivKey privateKey)
		{
			var hash = GetMessageHash();
			var signature = BSM.Sign(privateKey, hash.ReadOnlySpan);
			var address = privateKey.GetPubKey().ToAddress();
			return Sign(signature, address);
		}


		public bool Verify()
		{
			if (_sig == null)
			{
				throw new Exception("No signature data provided");
			}
			var hash = GetMessageHash();
			if (hash == KzUInt256.Zero)
			{
				throw new Exception("No tx data provided");
			}

			var signature = Convert.FromBase64String(_sig.Signature);
			var key = BSM.RecoverCompact(hash.ReadOnlySpan, signature);
			return key.ToAddress() == _sig.Address;
		}

		public KzUInt256 GetInputHash()
		{
			var vin = _refVin == -1 ? _targetVout : _refVin;
			return GetInputHashByVin(vin);
		}

		private KzUInt256 GetInputHashByVin(int vin)
		{
			if (_transaction.Vin.Count < vin)
			{
				var txIn = _transaction.Vin[vin];
				return KzHashes.SHA256(txIn.ScriptSig.ToBytes());
			}
			// using dummy hash
			return KzHashes.SHA256(new byte[32]);
		}

		// gets the Hash.sha256 for a given sigma instance within an output script
		// an example of 2 instances would be a user signature followed by a platform signature
		public KzUInt256 GetDataHash()
		{
			if (_transaction == null)
			{
				throw new Exception("No transaction provided");
			}
			var outputScript = _transaction.Vout[_targetVout].ScriptPub;

			var scriptChunks = outputScript.Ops;

			// loop over the script chunks and set the endIndex when the nTh instance is found
			var occurrences = 0;
			for (var i = 0; i < scriptChunks.Count; i++)
			{
				if (scriptChunks[i].ToVerboseString().ToUpper() == SigmaHex.ToUpper())
				{
					if (occurrences == _sigmaInstance)
					{
						// the -1 is to account for either the OP_RETURN
						// or "|" separator which is not signed
						var dataChunks = scriptChunks.Take(i - 1);
						var s = KzBScript.FromAsmString(dataChunks);
						return KzHashes.SHA256(s.ToBytes());
					}
					occurrences++;
				}
			}

			// If no endIndex found, return the hash for the entire script
			var dataScript = KzBScript.FromAsmString(scriptChunks);
			return KzHashes.SHA256(dataScript.ToBytes());
		}

		public KzBTxOut TargetTxOut
		{
			get { return _transaction.Vout[_targetVout]; }
		}

		public Sig Sig
		{
			get
			{
				var output = _transaction.Vout[_targetVout];
				var outputScript = output.ScriptPub;

				var scriptChunks = outputScript.Ops;
				var instances = new List<Sig>();

				for (var i = 0; i < scriptChunks.Count; i++)
				{
					if (scriptChunks[i].ToVerboseString().ToUpper() == SigmaHex.ToUpper())
					{
						var sig = new Sig
						{
							Algorithm = Encoding.UTF8.GetString(scriptChunks[i + 1].Op.GetBytes()),
							Address = Encoding.UTF8.GetString(scriptChunks[i + 2].Op.GetBytes()),
							Signature = Convert.ToBase64String(scriptChunks[i + 3].Op.GetBytes()),
							Vin = int.Parse(Encoding.UTF8.GetString(scriptChunks[i + 4].Op.GetBytes())),
						};

						instances.Add(sig);

						// Fast forward to the next possible instance position
						// 3 fields + 1 extra for the "|" separator
						i += 4;
					}
				}
				return instances.Count == 0 ? _sig : instances[_sigmaInstance];
			}
		}

		public int GetSigInstanceCount()
		{
			var existingAsm = TargetTxOut.ScriptPub.Ops;
			return existingAsm.Count(x => x.ToVerboseString().Equals(SigmaHex, StringComparison.OrdinalIgnoreCase));
		}

		public int GetSigInstancePosition()
		{
			var existingAsm = TargetTxOut.ScriptPub.Ops;
			return existingAsm.FindIndex(x => x.ToVerboseString().Equals(SigmaHex, StringComparison.OrdinalIgnoreCase));
		}
	}
}