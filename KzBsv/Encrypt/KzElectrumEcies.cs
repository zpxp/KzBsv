#region Copyright
// Copyright (c) 2020 TonesNotes
// Distributed under the Open BSV software license, see the accompanying file LICENSE.
#endregion
using Secp256k1Net;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace KzBsv
{
	/// <summary>
	/// Two parties set matching pairs of priv and pub keys.
	/// e.g. Alice sets her priv key and Bob's pub key. Bob sets his own priv key and Alice's pub key.
	/// The key pairs allow the derivation of two shared keys: kE and kM.
	/// kE is used as the encryption / decryption key.
	/// kM is used to sign the encrypted data to verify that what is received is what was sent.
	/// By default, the sender's pub key can be sent as part of the message.
	/// Set NoKey = true to omit sender's public key from the message sent. 
	/// Set ShortTag = true to reduce the content verification signature from 32 to 4 bytes.
	/// </summary>
	public class KzElectrumEcies
	{

		public KzPrivKey PrivateKey { get; set; }

		public KzPubKey PublicKey { get; set; }


		byte[] _iv;
		byte[] _kE;
		byte[] _kM;

		/// <summary>
		/// Two parties set matching pairs of priv and pub keys.
		/// e.g. Alice sets her priv key and Bob's pub key. Bob sets his own priv key and Alice's pub key.
		/// And the values of _kE and _kM will be equal.
		/// _kE is used as the encryption / decryption key.
		/// _kM is used to sign the encrypted data to verify that what is received is what was sent.
		/// </summary>
		void UpdatekEkM()
		{
			if (PrivateKey != null && PublicKey != null && PublicKey.IsValid)
			{
				using var secp = new Secp256k1();
				// Multiply the public key as an elliptic curve point by the private key a big number: 
				var bn = PrivateKey.BN;
				var pkbs = new byte[64];
				if (!secp.PublicKeyParse(pkbs.AsSpan(), PublicKey.ReadOnlySpan)) return;
				if (!secp.PubKeyTweakMul(pkbs.AsSpan(), PrivateKey.ReadOnlySpan)) return;
				var buffer = new byte[33];
				var x = pkbs.Slice(0, 32);
				var y = pkbs.Slice(32, 32);
				var yy = new BigInteger(y, true, false);
				if (yy.IsEven)
				{
					buffer[0] = 0x02;
				}
				else
				{
					buffer[0] = 0x03;
				}
				x.Reverse();
				x.CopyTo(buffer.AsSpan(1));

				// Hash the X coordinate of the resulting elliptic curve point.
				buffer.Reverse();
				var h = KzHashes.SHA512(buffer).ReadOnlySpan;
				_iv = new byte[16];
				h.Slice(0, 16).CopyTo(_iv);
				_kE = new byte[16];
				h.Slice(16, 16).CopyTo(_kE);
				_kM = new byte[32];
				h.Slice(32, 32).CopyTo(_kM);
			}
			else
			{
				throw new Exception("Invalid keys");
			}
		}

		public byte[] Encrypt(string message) => Encrypt(message.UTF8ToBytes());

		public string DecryptToUTF8(ReadOnlySpan<byte> data) => Decrypt(data).ToUTF8();

		public byte[] Encrypt(ReadOnlySpan<byte> data)
		{
			if (PrivateKey == null)
			{
				PrivateKey = new KzPrivKey().MakeNewKey(true);
			}
			UpdatekEkM();

			var cipherText = KzEncrypt.AesEncrypt(data, _kE, _iv, true);
			var BIE1 = Encoding.UTF8.GetBytes("BIE1");
			var rBuf = PrivateKey.GetPubKey().ReadOnlySpan;
			var len = BIE1.Length + rBuf.Length + cipherText.Length;
			var dataBytes = new byte[len];
			var spanData = dataBytes.AsSpan();
			BIE1.CopyTo(spanData.Slice(0));
			rBuf.CopyTo(spanData.Slice(BIE1.Length));
			cipherText.CopyTo(spanData.Slice(BIE1.Length + rBuf.Length));
			var hmac = KzHashes.HMACSHA256(_kM, spanData).ReadOnlySpan;
			var result = new byte[len + hmac.Length];
			var spanResult = result.AsSpan();
			spanData.CopyTo(spanResult.Slice(0));
			hmac.CopyTo(spanResult.Slice(spanData.Length));
			return result;
		}

		public byte[] Decrypt(ReadOnlySpan<byte> data)
		{
			var magic = data.Slice(0, 4);
			if (magic.ToHex() != Encoding.UTF8.GetBytes("BIE1").ToHex())
			{
				throw new Exception("Invalid magic");
			}

			var offset = 4;
			if (PublicKey == null)
			{
				var pub = data.Slice(4, 33);
				PublicKey = new KzPubKey(pub);
				offset = 37;
			}

			UpdatekEkM();
			var tagLength = 32;
			var cipherText = data.Slice(offset, data.Length - tagLength - offset);
			var hmac = data.Slice(data.Length - tagLength);
			var hmac2 = KzHashes.HMACSHA256(_kM, data.Slice(0, data.Length - tagLength)).ReadOnlySpan;

			if (hmac.ToHex() != hmac2.ToHex())
			{
				throw new Exception("Invalid checksum");
			}

			var r = KzEncrypt.AesDecrypt(cipherText, _kE, _iv);
			return r;
		}
	}
}
