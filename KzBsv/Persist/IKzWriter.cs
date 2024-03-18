#region Copyright
// Copyright (c) 2020 TonesNotes
// Distributed under the Open BSV software license, see the accompanying file LICENSE.
#endregion
using System;
using System.Buffers;

namespace KzBsv
{
	public interface IKzWriter
	{
		public IKzWriter Add(ReadOnlySpan<byte> data);
		public IKzWriter Add(ReadOnlySequence<byte> data);

		public IKzWriter Add(UInt64 v);
		public IKzWriter Add(Int64 v);
		public IKzWriter Add(UInt32 v);
		public IKzWriter Add(Int32 v);
		public IKzWriter Add(byte v);
		public IKzWriter Add(KzUInt160 v);
		public IKzWriter Add(KzUInt256 v);
		public IKzWriter Add(KzUInt512 v);
	}

	public static class KzExtensionsIWriter
	{
		public static IKzWriter Add(this IKzWriter w, KzScript script, bool withoutCodeSeparators = false) => script.AddTo(w, withoutCodeSeparators);
		public static IKzWriter Add(this IKzWriter w, KzOutPoint op) => op.AddTo(w);
		public static IKzWriter Add(this IKzWriter w, KzTxIn txIn, bool useBip239) => txIn.AddTo(w, useBip239);
		public static IKzWriter Add(this IKzWriter w, KzTxOut txOut) => txOut.AddTo(w);
		public static IKzWriter Add(this IKzWriter w, KzTransaction tx, bool useBip239) => tx.AddTo(w, useBip239);
		public static IKzWriter Add(this IKzWriter w, KzOp op) => op.AddTo(w);

		//public static KzIWriter Add<T>(this KzIWriter w, T[] vs) { foreach (var v in vs) v.Add(w); return w; }
	}
}
