#region Copyright
// Copyright (c) 2020 TonesNotes
// Distributed under the Open BSV software license, see the accompanying file LICENSE.
#endregion
using System;
using System.Buffers;
using System.IO;
using Xunit;
using System.Linq;
using KzBsv;
using System.Security.Cryptography;
using System.Text;

namespace Tests.KzBsv.Protocols
{
	public class SigmaTest
	{
		private readonly KzPrivKey privateKey;
		private readonly KzPrivKey privateKey2;
		private KzBTransaction tx;

		private KzTxIn GetTxIn(string hash = "810755d937913d4228e1a4d192046d96c0642e2678d6a90e1cb794b0c2aeb78b")
		{
			var script = KzBScript.ParseAsm("OP_DUP OP_HASH160 5a009731beae590247297ecee0b1b54aa4b96c5d OP_EQUALVERIFY OP_CHECKSIG");
			return new KzTxIn(
					new KzOutPoint(new KzUInt256(hash), 0),
					script.ToScript(),
					KzTxIn.SEQUENCE_FINAL);
		}

				private KzTxIn GetTxIn2(string hash = "810755d937913d4228e1a4d192046d96c0642e2678d6a90e1cb794b0c2aeb78c")
		{
			var script = KzBScript.ParseAsm("OP_DUP OP_HASH160 5a009731beae590247297ecee0b1b54aa4b96c5a OP_EQUALVERIFY OP_CHECKSIG");
			return new KzTxIn(
					new KzOutPoint(new KzUInt256(hash), 0),
					script.ToScript(),
					KzTxIn.SEQUENCE_FINAL);
		}

		public SigmaTest()
		{
			privateKey = KzPrivKey.FromWIF("KzmFJcMXHufPNHixgHNwXBt3mHpErEUG6WFbmuQdy525DezYAi82");
			privateKey2 = KzPrivKey.FromWIF("L1U5FS1PzJwCiFA43hahBUSLytqVoGjSymKSz5WJ92v8YQBBsGZ1");
			var script = new KzBScript()
				.Add(KzOpcode.OP_0)
				.Add(KzOpcode.OP_RETURN)
				.Add(KzOpcode.OP_PUSHDATA1)
				.Add(KzOpcode.OP_PUSHDATA2);

			tx = new KzBTransaction();
			tx.AddOut(script, 0L);
		}

		[Fact]
		public void ItSignsAndVerifiesAMessage()
		{
			var sigma = new Sigma(tx);
			var res = sigma.Sign(privateKey);
			var valid = sigma.Verify();
			Assert.True(valid);
		}


		[Fact]
		public void BSMTest()
		{
			var message = Encoding.UTF8.GetBytes("message");
			var signature = BSM.Sign(privateKey, message);
			var key = BSM.RecoverCompact(message, signature);
			var addy = privateKey.GetPubKey().ToAddress();
			Assert.Equal(addy, key.ToAddress());
		}


		[Fact]
		public void GeneratesCorrectOutputScript()
		{
			// Create a new Sigma instance with the transaction and targetVout
			Sigma sigma = new Sigma(tx, 0, 0);
			var txOut = sigma.Transaction.Vout[0];
			var asm = txOut.ScriptPub.ToString();

			// Sign the message
			var result = sigma.Sign(privateKey);

			string asmAfter = result.SignedTx.Vout[0].ScriptPub.ToString();

			Assert.NotEqual(asmAfter, asm);
		}

		[Fact]
		public void SignedTxIsVerified()
		{
			// Create a new Sigma instance with the transaction and targetVout
			Sigma sigma = new Sigma(tx, 0, 0);

			// Sign the message
			var result = sigma.Sign(privateKey);

			string inputHash = sigma.GetInputHash().ToHex();
			string dataHash = sigma.GetDataHash().ToHex();
			string messageHash = sigma.GetMessageHash().ToHex();

			Sigma sigma2 = new Sigma(result.SignedTx);

			string inputHash2 = sigma2.GetInputHash().ToHex();
			string dataHash2 = sigma2.GetDataHash().ToHex();
			string messageHash2 = sigma2.GetMessageHash().ToHex();

			Assert.Equal(inputHash2, inputHash);
			Assert.Equal(dataHash2, dataHash);
			Assert.Equal(messageHash2, messageHash);

			Assert.Equal(1, sigma2.GetSigInstanceCount());

			Assert.True(sigma2.Verify());
		}

		[Fact]
		public void ReplaceDummySignatureWithRealOne()
		{
			// Sign before adding inputs to create a dummy signature
			Sigma sigma = new Sigma(tx, 0, 0);
			var inputHash = sigma.GetInputHash();
			var dataHash = sigma.GetDataHash();

			// Add some inputs
			var txIn1 = GetTxIn();
			tx.AddIn(txIn1);

			// Input hash should change after adding inputs
			Assert.NotEqual(sigma.GetInputHash(), inputHash);

			// Sign again now that inputs have been added
			sigma.Sign(privateKey);

			// Data hash should not change after replacing dummy signature
			Assert.Equal(sigma.GetDataHash(), dataHash);

			Assert.True(sigma.Verify());
		}

		[Fact]
		public void SpecifyAnInputToSign()
		{
			// Add some inputs
			var txIn1 = GetTxIn();
			var txIn2 = GetTxIn2();
			tx.AddIn(txIn1);
			tx.AddIn(txIn2);

			var sigma1 = new Sigma(tx, 0, 0, 0);

			// Sign again now that inputs have been added
			sigma1.Sign(privateKey);
			Assert.True(sigma1.Verify());

			var sigma2 = new Sigma(tx, 0, 0, 1);

			// Sign again now that inputs have been added
			sigma2.Sign(privateKey);
			Assert.True(sigma2.Verify());

			Assert.NotEqual(sigma1.Sig.Signature, sigma2.Sig.Signature);
		}

		[Fact]
		public void CreateUserAndPlatformSignatureOnSameOutput()
		{
			Sigma sigma = new Sigma(tx, 0, 0);

			// Sign the tx
			var result = sigma.Sign(privateKey);

			Assert.True(sigma.Verify());

			// Create another Sigma instance on the same tx, and same output
			Sigma sigma2 = new Sigma(result.SignedTx, 0, 1);

			// Add a second signature with a 2nd key
			sigma2.Sign(privateKey2);

			Assert.True(sigma2.Verify());
			Assert.Equal(2, sigma2.GetSigInstanceCount());

			// Check the address for instance 1
			sigma2.SetSigmaInstance(0);
			string address = sigma2.Sig.Address;
			Assert.Equal("1ACLHVPVnB8AmLCyD5hPQtPCSCccjiUn7H", address);

			// Check the address for instance 2
			sigma2.SetSigmaInstance(1);
			string address2 = sigma2.Sig.Address;
			Assert.Equal("1Cz3gyTgV7QgMoU6j51pvHdzeeapXfXDtA", address2);
		}


		[Fact]
		public void ValidateSignatureFromBundled1SatLib()
		{

			string hex = "0100000001d70d11131d80dcee954926de96d793585c6bc0ed69619a6cc761a20cef1b1bd7010000006a4730440220466ca5d42bd7a8bd2b6ea5770970b03a0c39fa29847f31e0d949dd36bf523b910220379d1c2718ae3300e833201b227ed8159c93f85bcc6eaea4028dafed2559fee24121036232d22ae556320f5a6516e6e75eab89b33760ccf7b3eb5b791a23883da6b1f5ffffffff020100000000000000a776a914c8fcb96f2f16175d37d602c438eb2f64e59e217788ac0063036f7264510a746578742f706c61696e000774657374696e67686a055349474d410342534d22314535533931716e6f4743586d36314d5931617842435a436d4d50414d5a3675457a41206798f75d8b2bc6b6f2b536a9702dac3533528574d6f46acd8e2747ba63a0e70e146adba068c93e2979d010baf9aa47a1daf501381620adc59a09e10508aff46e013015e16005000000001976a9148d3164e5ed6f5ae76d7cb3860b31af4f369e775d88ac00000000";
			var tx = KzTransaction.ParseHex(hex);
			Sigma sigma = new Sigma(tx, 0, 0);
			bool isValid = sigma.Verify();
			Assert.True(isValid);
		}


	}
}
