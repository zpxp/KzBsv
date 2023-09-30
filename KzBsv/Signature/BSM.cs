using Secp256k1Net;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace KzBsv
{

	public static class BSM
	{
		const string _messageMagic = "Bitcoin Signed Message:\n";

		static KzUInt256 GetMessageHash(ReadOnlySpan<byte> message)
		{
			var messagehash = KzHashes.SHA256(message).ToHex();
			return new KzWriterHash().Add(_messageMagic).Add(messagehash).GetHashFinal();
		}

		public static byte[] Sign(KzPrivKey priv, ReadOnlySpan<byte> message)
		{
			var hash = GetMessageHash(message);
			var (ok, sig) = priv.SignCompact(hash);
			if (!ok)
			{
				throw new Exception("BSM Signature not ok");
			}
			return sig;
		}

		public static KzPubKey RecoverCompact(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
		{
			var hash = GetMessageHash(message);
			var (ok, key) = KzPubKey.FromRecoverCompact(hash, signature);
			if (!ok)
			{
				throw new Exception("BSM Cannot recover key");
			}
			return key;
		}

		public static bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, string address)
		{
			var hash = GetMessageHash(message);
			var pubKey = new KzPubKey();
			if (!pubKey.RecoverCompact(hash, signature))
			{
				throw new Exception("BSM Cannot retrieve pub key from sig");
			}
			if (address != pubKey.ToAddress())
			{
				throw new Exception($"BSM Verify address does not match. Expected {address} got {pubKey.ToAddress()}");
			}
			var ok = pubKey.Verify(hash, signature);
			return ok;
		}
	}
}
