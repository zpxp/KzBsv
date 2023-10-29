#region Copyright
// Copyright (c) 2020 TonesNotes
// Distributed under the Open BSV software license, see the accompanying file LICENSE.
#endregion

using System;
using System.Text.RegularExpressions;

namespace KzBsv
{
	public class KzPaymail
	{
		public enum Capability
		{
			pki,
			paymentDestination,
			senderValidation,
			verifyPublicKeyOwner,
			receiverApprovals,
			payToProtocolPrefix,
			p2pTx,
			p2pPaymentDestination
		}

		/// <summary>
		/// BRFC IDs are partially defined here: http://bsvalias.org
		/// </summary>
		/// <param name="c"></param>
		/// <returns></returns>
		public static string ToBrfcId(Capability c)
		{
			return c switch
			{
				Capability.pki => "pki",
				Capability.paymentDestination => "paymentDestination",
				Capability.senderValidation => "6745385c3fc0",
				Capability.verifyPublicKeyOwner => "a9f510c16bde",
				Capability.receiverApprovals => "c318d09ed403",
				Capability.payToProtocolPrefix => "7bd25e5a1fc6",
				Capability.p2pTx => "5f1323cddf31",
				Capability.p2pPaymentDestination => "2a40af698840",
				_ => null
			};
		}

		const string HandleRegexPattern = @"^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";
		static Lazy<Regex> lazyHandleRegex;

		static KzPaymail()
		{
			lazyHandleRegex = new Lazy<Regex>(() => new Regex(HandleRegexPattern), true);
		}

		public static (bool ok, string alias, string domain) Parse(string paymail)
		{
			var ok = lazyHandleRegex.Value.IsMatch(paymail);
			if (!ok)
				return (false, null, null);
			var parts = paymail.Split('@');
			var alias = parts[0];
			var domain = parts[1];
			return (true, alias, domain);
		}

		public static bool IsValid(string paymail) => KzPaymail.Parse(paymail).ok;

		public static bool IsValid(string alias, string domain, string tld) => KzPaymail.Parse($"{alias}@{domain}.{tld}").ok;

		public class P2PTxContract
		{
			public string hex { get; set; }
			public string reference { get; set; }

			public M metadata { get; set; }

			public class M
			{
				public string? sender { get; set; }
				public string? pubkey { get; set; }
				public string? signature { get; set; }
				public string? note { get; set; }
			}
		}
	}
}
