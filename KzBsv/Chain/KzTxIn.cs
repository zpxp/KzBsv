﻿#region Copyright
// Copyright (c) 2020 TonesNotes
// Distributed under the Open BSV software license, see the accompanying file LICENSE.
#endregion
using System;
using System.Buffers;

namespace KzBsv
{

	/// <summary>
	/// Closely mirrors the data and layout of a Bitcoin transaction input as stored in each block.
	/// Focus is on performance when processing large numbers of transactions, including blocks of transactions.
	/// Not used for making dynamic changes (building scripts).
	/// See <see cref="KzBTxIn"/> when dynamically building a transaction input.
	/// <seealso cref="KzTransaction"/>
	/// </summary>
	public struct KzTxIn
	{
		/// <summary>
		/// Setting nSequence to this value for every input in a transaction disables nLockTime.
		/// </summary>
		public const UInt32 SEQUENCE_FINAL = 0xffff_ffff;

		KzOutPoint _prevout;
		KzAmount _prevSatoshis;
		KzScript _prevScriptOut;
		KzScript _scriptSig;
		UInt32 _sequence;

		public KzOutPoint PrevOut => _prevout;
		public KzScript PrevOutScript => _prevScriptOut;
		public KzScript ScriptSig => _scriptSig;
		public UInt32 Sequence => _sequence;

		public KzTxIn(KzOutPoint prevout, KzAmount prevSatoshis, KzScript prevScriptOut, KzScript scriptSig, UInt32 sequence)
		{
			_prevout = prevout;
			_prevSatoshis = prevSatoshis;
			_prevScriptOut = prevScriptOut;
			_scriptSig = scriptSig;
			_sequence = sequence;
		}

		public bool TryParseTxIn(ref SequenceReader<byte> r, IKzBlockParser bp)
		{
			if (!_prevout.TryReadOutPoint(ref r)) goto fail;

			bp.TxInStart(this, r.Consumed);

			if (!_scriptSig.TryParseScript(ref r, bp)) goto fail;
			if (!r.TryReadLittleEndian(out _sequence)) goto fail;

			bp.TxInParsed(this, r.Consumed);

			return true;
		fail:
			return false;
		}

		public bool TryReadTxIn(ref SequenceReader<byte> r, bool readBip239 = false)
		{
			if (!_prevout.TryReadOutPoint(ref r)) goto fail;
			if (!_scriptSig.TryReadScript(ref r)) goto fail;
			if (!r.TryReadLittleEndian(out _sequence)) goto fail;

			if (readBip239)
			{
				if (!r.TryReadExact(8, out var val)) goto fail;
				_prevSatoshis = BitConverter.ToInt64(val.ToSpan());
				if (!_prevScriptOut.TryReadScript(ref r)) goto fail;
			}

			return true;
		fail:
			return false;
		}

		public IKzWriter AddTo(IKzWriter writer, bool useBip239)
		{
			writer
				 .Add(_prevout)
				 .Add(_scriptSig)
				 .Add(_sequence);

			if (useBip239)
			{
				writer.Add(_prevSatoshis);
				writer.Add(_prevScriptOut);
			}
			return writer;
		}
	}
}
