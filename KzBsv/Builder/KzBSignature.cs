using Newtonsoft.Json;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace KzBsv
{

	public class KzBSignature
	{
		public KzBSignature(KzUInt256 hashTx, int outputIdx, byte[] signature)
		{
			HashTx = hashTx;
			OutputIdx = outputIdx;
			Signature = signature;
		}

		public KzUInt256 HashTx { get; set; }
		public int OutputIdx { get; set; }
		public byte[] Signature { get; set; }
	}
}
