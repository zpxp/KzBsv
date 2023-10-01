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

		/// <summary>
		/// this is the grottiest shit ive ever seen but has to be copied the same from rust sv lib. these fucking rust devs are wack insane
		/// </summary>
		static void WriteVarInt(List<byte> buff, ulong varint)
		{
			if (varint <= 252)
			{
				buff.Add((byte)varint);
			}
			else if (varint <= 0xffff)
			{
				buff.Add(0xfd);
				buff.AddRange(BitConverter.GetBytes((UInt16)varint));
			}
			else if (varint <= 0xffffffff)
			{
				buff.Add(0xfe);
				buff.AddRange(BitConverter.GetBytes((UInt32)varint));
			}
			else 
			{
				buff.Add(0xff);
				buff.AddRange(BitConverter.GetBytes(varint));
			}
		}

		static KzUInt256 GetMagic(ReadOnlySpan<byte> message)
		{
			var magic = Encoding.UTF8.GetBytes(_messageMagic);
			var buff = new List<byte>(message.Length + magic.Length + 8);
			WriteVarInt(buff, (ulong)magic.Length);
			buff.AddRange(magic);
			WriteVarInt(buff, (ulong)message.Length);
			buff.AddRange(message.ToArray());

			return KzHashes.HASH256(buff.ToArray());
		}

		public static byte[] Sign(KzPrivKey priv, ReadOnlySpan<byte> message)
		{
			var hash = GetMagic(message);
			var (ok, sig) = priv.SignCompact(hash);
			if (!ok)
			{
				throw new Exception("BSM Signature not ok");
			}
			return sig;
		}

		public static KzPubKey RecoverCompact(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
		{
			var hash = GetMagic(message);
			var (ok, key) = KzPubKey.FromRecoverCompact(hash, signature);
			if (!ok)
			{
				throw new Exception("BSM Cannot recover key");
			}
			return key;
		}

		public static bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, string address)
		{
			var hash = GetMagic(message);
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
