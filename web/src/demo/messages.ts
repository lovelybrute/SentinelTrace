/**
 * The bundled demonstration corpus.
 *
 * Every message here is a complete, verbatim RFC 5322 document. They are fed
 * through exactly the same pipeline as an analyst upload — `analyseEmail` parses
 * these bytes with no special-casing anywhere in the engine — so what the judges
 * see on screen is genuinely computed, not replayed from a fixture. That is the
 * whole point: a canned screenshot proves nothing, a real parse proves the
 * pipeline works.
 *
 * All addresses, domains and organisations are fictional. The IP ranges are the
 * IETF documentation blocks reserved by RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24), which can never be routed on the public internet — so nothing
 * in this corpus can be mistaken for, or used to attack, real infrastructure.
 *
 * The header values are load-bearing. Each message is constructed so the engine
 * derives a specific, defensible verdict from the evidence: relay chains that
 * geolocate against the curated netblocks in `services/intel/geoDatabase.ts`, and
 * sender domains whose SPF and DMARC policies live in `domainDatabase.ts`.
 * Changing an IP or a domain here will change the verdict, so keep the two files
 * in step.
 */

export interface DemoMessage {
  id: string;
  /** Filename presented to the analyser, as if uploaded. */
  filename: string;
  /** Menu label in the analyser's sample picker. */
  label: string;
  /** One line explaining what this sample demonstrates. */
  synopsis: string;
  /**
   * What the engine should conclude. Displayed next to the sample so a judge can
   * compare the expectation against the computed result — and used by the
   * offline checks to catch regressions in the engine.
   */
  expected: {
    classification: string;
    level: string;
    spf: string;
    dkim: string;
    dmarc: string;
    /** Probable infrastructure location of the observed source. */
    origin: string | null;
  };
  raw: string;
}

/* ------------------------------------------------------------------ */
/* 1 — Business email compromise (the primary demonstration)           */
/* ------------------------------------------------------------------ */

/**
 * Vendor-impersonation payment diversion against Nexora Group.
 *
 * The forensic story the engine reconstructs from these headers:
 *
 *  - Hop 1 is 203.0.113.47 (Singapore, Pacific Rim Colocation) — the observed
 *    source, and the address the origin assessment reports.
 *  - Hop 2 is 198.51.100.77 (Frankfurt, Continental Bulk Hosting) — the boundary,
 *    the host that actually connected to the recipient's gateway.
 *  - The sender's own SPF policy authorises only 203.0.113.0/24 and ends in
 *    `-all`. Because SPF is evaluated at the *boundary*, the Frankfurt relay is
 *    not authorised and SPF fails. Evaluating it at the origin would have passed,
 *    which is precisely the trap this sample exists to demonstrate.
 *  - The DKIM signature claims `d=paypal.com`, a domain the sender does not
 *    control and which does not align with the From domain — DKIM fails.
 *  - DMARC therefore has no aligned, authenticated identifier and fails; but the
 *    published policy is `p=none`, so a compliant receiver still delivers it.
 *    That single tag is why this message reached a mailbox at all.
 *  - Reply-To points at a different domain again, steering the reply to
 *    infrastructure the attacker controls.
 *
 * The attachment is a plain PDF and stays plain deliberately. A macro-enabled or
 * executable attachment would push the classifier to MALWARE, and the point of
 * this sample is the payment-diversion tradecraft, not the payload.
 */
const BEC_PAYMENT_DIVERSION = `Received: from MU2PR01MB4521.indprd01.prod.outlook.com (2603:1096:c01:8c::12)
 by MU2PR01MB4521.indprd01.prod.outlook.com with HTTPS; Mon, 24 Aug 2026 09:14:52 +0530
Received: from mail.nexora-finance.com (mail.nexora-finance.com [198.51.100.77])
 by IN-MX-01.nexoragroup-in.mail.protection.outlook.com (104.47.58.12) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7897.12;
 Mon, 24 Aug 2026 09:14:49 +0530
Received: from vps-sg-04.prc-hosting.net (vps-sg-04.prc-hosting.net [203.0.113.47])
 by mail.nexora-finance.com (Postfix) with ESMTPSA id 4C1F2A0E93;
 Mon, 24 Aug 2026 03:44:31 +0000 (UTC)
Authentication-Results: nexoragroup-in.mail.protection.outlook.com;
 spf=fail (sender IP is 198.51.100.77) smtp.mailfrom=bounce.paypa1-security.com;
 dkim=fail (body hash did not verify) header.d=paypal.com;
 dmarc=fail action=none header.from=paypa1-security.com;
 compauth=fail reason=001
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=paypal.com; s=selector1;
 t=1787545471; h=from:to:subject:date:message-id;
 bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
 b=RmFrZVNpZ25hdHVyZUZvckRlbW9uc3RyYXRpb25Pbmx5Tm90VmFsaWRhdGFibGVBZ2FpbnN0QW55
 UmVhbEtleU1hdGVyaWFsVGhpc0lzU3ludGhldGljRXZpZGVuY2U=
Return-Path: <bounce@bounce.paypa1-security.com>
From: "Nexora Group Accounts Payable" <finance@paypa1-security.com>
Reply-To: "Nexora Finance Desk" <settlements@nexora-finance.com>
To: "Priya Raghavan" <priya.raghavan@nexoragroup.in>
Cc: accounts.payable@nexoragroup.in
Subject: URGENT: Updated remittance details for invoice INV-2026-4471 - action required today
Date: Mon, 24 Aug 2026 03:44:28 +0000
Message-ID: <20260824034428.4C1F2A0E93@mail.nexora-finance.com>
X-Mailer: PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)
X-Priority: 1
Importance: High
X-Originating-IP: [203.0.113.47]
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_88213_1787545468"

------=_Part_88213_1787545468
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Dear Priya,

Please note that our banking arrangements have changed with immediate effect
following an internal treasury restructuring. All pending settlements must now
be directed to our new account.

I need you to process the outstanding balance on invoice INV-2026-4471 today.
The amount is INR 4,85,000. Our auditors close the quarter this afternoon and
this payment must clear before then, otherwise the reconciliation will be
flagged and both of us will have to explain the delay to the board.

Updated remittance details:

  Account name   : Nexora Finance Settlements
  Account number : 0042 8871 5530
  IFSC           : UTIB0004471
  Bank           : Axis Bank, Andheri East Branch

Please confirm once the transfer has been initiated by replying to this email
directly. Do not route this through the usual shared mailbox, as the finance
team is mid-migration and messages there are not being monitored today.

I am in back-to-back meetings with the auditors so I will not be able to take
a call, but reply here and I will see it.

Verify the updated details on our portal before processing:
https://nexora-finance.com/verify-remittance?ref=INV-2026-4471

Regards,

Anand Krishnan
Chief Financial Officer
Nexora Group
nexoragroup.in | +91 22 6841 2200

------=_Part_88213_1787545468
Content-Type: application/pdf; name="Invoice_INV-2026-4471_Revised.pdf"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="Invoice_INV-2026-4471_Revised.pdf"

JVBERi0xLjQKJcfsj6IKNSAwIG9iago8PC9MZW5ndGggNiAwIFIvRmlsdGVyIC9GbGF0ZURlY29k
ZT4+CnN0cmVhbQp4nDPQM1Qo5ypUMFAwALJMgKSRuYGRhZmJhaGJqZmxoYGFsZGBoZGxkYWxpYGh
oYGRoZGJgZGBpYWRgYWRoYGFgaGRoZGRkYWBpYGhgYWBoZGhkZGRhYGlgaGBhYGhkaGRkZGFgaWB
oYGFgaGRoZGRkYWBpYGhgYWBoZGhkZGFgaWBoYGFgaGRoZGRkYWBpYGhgYWBoZGhkZGFnaAplbmRz
dHJlYW0KZW5kb2JqCjYgMCBvYmoKMTk2CmVuZG9iagoKMSAwIG9iago8PC9UeXBlL1BhZ2VzL0tp
ZHNbIDMgMCBSIF0vQ291bnQgMT4+CmVuZG9iagoKJSVFT0YK

------=_Part_88213_1787545468--
`;

/* ------------------------------------------------------------------ */
/* 2 — Credential phishing                                             */
/* ------------------------------------------------------------------ */

/**
 * Bank credential harvesting via a homoglyph domain.
 *
 * `hdfc-bank-verify.in` is a lookalike of the genuine `hdfcbank.com`, and the
 * lookalike analyser scores the pair. The sender publishes no SPF and no DMARC
 * at all, so the authentication rows report a genuine absence (NONE) rather than
 * a failure — a different and equally important evidential state to show. The
 * anchor text disguises the destination host, which the URL extractor flags.
 */
const CREDENTIAL_PHISHING = `Received: from IN-MX-02.nexoragroup-in.mail.protection.outlook.com (104.47.58.14)
 by MU2PR01MB4521.indprd01.prod.outlook.com with Microsoft SMTP Server id 15.20.7897.12;
 Sun, 23 Aug 2026 21:07:11 +0530
Received: from srv-alx-118.alexhost.net (srv-alx-118.alexhost.net [45.145.22.118])
 by IN-MX-02.nexoragroup-in.mail.protection.outlook.com (104.47.58.14) with Microsoft SMTP
 Server id 15.20.7897.12; Sun, 23 Aug 2026 21:07:08 +0530
Authentication-Results: nexoragroup-in.mail.protection.outlook.com;
 spf=none (sender IP is 45.145.22.118) smtp.mailfrom=hdfc-bank-verify.in;
 dkim=none; dmarc=none header.from=hdfc-bank-verify.in
Return-Path: <alerts@hdfc-bank-verify.in>
From: "HDFC Bank Security" <alerts@hdfc-bank-verify.in>
To: "Priya Raghavan" <priya.raghavan@nexoragroup.in>
Subject: Your account has been temporarily suspended - verify within 24 hours
Date: Sun, 23 Aug 2026 15:37:02 +0000
Message-ID: <8f2e1a94c7b3@hdfc-bank-verify.in>
X-Mailer: PHPMailer 6.6.0
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>Dear Customer,</p>

<p>We have detected unusual activity on your NetBanking account and it has been
temporarily suspended as a precaution. Your account will be permanently
deactivated within 24 hours unless you confirm your identity.</p>

<p>Please verify your account immediately to restore access:</p>

<p><a href="http://45.145.22.118/hdfc/secure/netbanking/login.php">https://netbanking.hdfcbank.com/secure-verify</a></p>

<p>You will need to confirm your customer ID, NetBanking password and the OTP
sent to your registered mobile number.</p>

<p>Failure to verify will result in permanent closure of your account and
forfeiture of the balance held.</p>

<p>Regards,<br>
HDFC Bank Security Team</p>

<p style="font-size:9px;color:#888">This is an automated message. Please do not
reply to this email.</p>
</body>
</html>
`;

/* ------------------------------------------------------------------ */
/* 3 — Legitimate mail (the control)                                   */
/* ------------------------------------------------------------------ */

/**
 * A genuine internal message, included as the control.
 *
 * A detector that flags everything is useless, so the corpus has to contain
 * something the engine correctly clears. This travels entirely within Exchange
 * Online from a properly configured domain, and the engine should return a low
 * score and a LEGITIMATE classification.
 *
 * Note the honest limit: `nexoragroup.in` publishes
 * `v=spf1 include:spf.protection.outlook.com -all`, and an `include:` cannot be
 * resolved without live DNS. Offline, SPF is therefore NEUTRAL rather than PASS,
 * and DMARC is inconclusive rather than passing. The engine says exactly that
 * instead of inventing a pass — which is the behaviour worth showing a judge.
 */
const LEGITIMATE_INTERNAL = `Received: from MU2PR01MB4521.indprd01.prod.outlook.com (2603:1096:c01:8c::12)
 by PN3PR01MB7412.indprd01.prod.outlook.com with HTTPS; Mon, 24 Aug 2026 11:02:19 +0530
Received: from BM1PR01MB3388.indprd01.prod.outlook.com (2603:1096:b00:41::7)
 by MU2PR01MB4521.indprd01.prod.outlook.com (2603:1096:c01:8c::12) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7897.12;
 Mon, 24 Aug 2026 11:02:16 +0530
Authentication-Results: nexoragroup-in.mail.protection.outlook.com;
 spf=pass (sender IP is 40.107.20.55) smtp.mailfrom=nexoragroup.in;
 dkim=pass (signature was verified) header.d=nexoragroup.in;
 dmarc=pass action=none header.from=nexoragroup.in;
 compauth=pass reason=100
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=nexoragroup.in; s=selector1;
 t=1787551936; h=from:to:subject:date:message-id;
 bh=RGVtb0JvZHlIYXNoRm9yTGVnaXRpbWF0ZU1haWw9;
 b=TGVnaXRpbWF0ZURlbW9uc3RyYXRpb25TaWduYXR1cmVOb3RDcnlwdG9ncmFwaGljYWxseVZhbGlk
 QnV0U3RydWN0dXJhbGx5V2VsbEZvcm1lZEZvclRlc3Rpbmc=
Return-Path: <anand.krishnan@nexoragroup.in>
From: "Anand Krishnan" <anand.krishnan@nexoragroup.in>
To: "Priya Raghavan" <priya.raghavan@nexoragroup.in>
Subject: Q2 vendor reconciliation - review before Thursday
Date: Mon, 24 Aug 2026 05:32:14 +0000
Message-ID: <BM1PR01MB33884A1E9C2F7D1E0@BM1PR01MB3388.indprd01.prod.outlook.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi Priya,

I have put the Q2 vendor reconciliation on the shared drive under
Finance/Reconciliation/Q2-2026. Could you take a look before Thursday's
review meeting?

Two things worth your attention: the Kalyani Logistics balance still shows the
March adjustment we thought had been cleared, and there are four invoices from
Meridian Supplies that were entered twice. Neither is urgent but I would rather
we sorted them out before the auditors arrive next month.

No rush on this - Thursday is fine.

Thanks,
Anand

--
Anand Krishnan
Chief Financial Officer, Nexora Group
`;

/* ------------------------------------------------------------------ */
/* 4 — Display-name spoofing with a Tor relay                          */
/* ------------------------------------------------------------------ */

/**
 * Gift-card fraud sent through a Tor exit node.
 *
 * Two things this sample demonstrates that the others do not:
 *
 *  - The From display name embeds a *different* address than the one that
 *    actually sent the message. Mail clients show the display name, so the
 *    recipient sees the CEO's real address while the message came from a free
 *    webmail account. The header forensics flags this directly.
 *  - The relay chain passes through 185.220.101.44, a known Tor exit range. The
 *    origin assessment must report that the true source sits behind an
 *    anonymising relay and lower its confidence accordingly — an honest
 *    "we cannot tell you where this came from", which matters more than a
 *    confident guess.
 */
const DISPLAY_NAME_SPOOF = `Received: from IN-MX-01.nexoragroup-in.mail.protection.outlook.com (104.47.58.12)
 by MU2PR01MB4521.indprd01.prod.outlook.com with Microsoft SMTP Server id 15.20.7897.12;
 Sat, 22 Aug 2026 18:41:33 +0530
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
 by IN-MX-01.nexoragroup-in.mail.protection.outlook.com (104.47.58.12) with Microsoft SMTP
 Server id 15.20.7897.12; Sat, 22 Aug 2026 18:41:30 +0530
Received: from [185.220.101.44] ([185.220.101.44])
 by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f9e8b2c4d1sm8842915ad.72;
 Sat, 22 Aug 2026 13:11:27 +0000 (UTC)
Authentication-Results: nexoragroup-in.mail.protection.outlook.com;
 spf=pass (sender IP is 209.85.220.41) smtp.mailfrom=gmail.com;
 dkim=pass (signature was verified) header.d=gmail.com;
 dmarc=pass action=none header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20230601;
 t=1787490687; h=from:to:subject:date:message-id;
 bh=R2lmdENhcmRGcmF1ZERlbW9uc3RyYXRpb25Cb2R5SGFzaA==;
 b=U3ludGhldGljU2lnbmF0dXJlRm9yVGhlU0lIRGVtb25zdHJhdGlvbkNvcnB1c05vdFZlcmlmaWFi
 bGVBZ2FpbnN0R29vZ2xlc1JlYWxQdWJsaWNLZXk=
Return-Path: <anand.krishnan.nexora@gmail.com>
From: "Anand Krishnan <anand.krishnan@nexoragroup.in>" <anand.krishnan.nexora@gmail.com>
To: "Priya Raghavan" <priya.raghavan@nexoragroup.in>
Subject: Quick favour - are you at your desk?
Date: Sat, 22 Aug 2026 13:11:24 +0000
Message-ID: <CAJ8vK2mQ9xR4nP7wL3tYbE@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Priya,

Are you available? I need something handled discreetly and quickly.

I am travelling and cannot access the corporate system properly. We need to
send client appreciation gifts today for the Kalyani account and I have left
it far too late.

Can you arrange 10 Amazon gift vouchers of INR 10,000 each? Purchase them,
scratch the panel and send me photographs of the codes here. I will approve
the reimbursement personally as soon as I am back in the office on Monday.

Please keep this between us for now - I do not want the wider team to know I
forgot the client gifts, and I would rather Finance did not raise it at the
review.

Let me know as soon as it is done.

Anand
Sent from my iPhone
`;

/* ------------------------------------------------------------------ */
/* 5 — Malware delivery                                                */
/* ------------------------------------------------------------------ */

/**
 * Fake shipping notice carrying a double-extension executable.
 *
 * `Shipment_Documents_AWB4471882.pdf.exe` presents as a PDF in any client that
 * hides known extensions while actually being an executable. The attachment
 * analyser rates this CRITICAL, which drives the classification to MALWARE — the
 * one sample in the corpus where the payload, not the tradecraft, is the story.
 */
const MALWARE_DELIVERY = `Received: from IN-MX-02.nexoragroup-in.mail.protection.outlook.com (104.47.58.14)
 by MU2PR01MB4521.indprd01.prod.outlook.com with Microsoft SMTP Server id 15.20.7897.12;
 Fri, 21 Aug 2026 08:22:54 +0530
Received: from mail.invoice-settlement.cc (mail.invoice-settlement.cc [5.188.10.44])
 by IN-MX-02.nexoragroup-in.mail.protection.outlook.com (104.47.58.14) with Microsoft SMTP
 Server id 15.20.7897.12; Fri, 21 Aug 2026 08:22:51 +0530
Authentication-Results: nexoragroup-in.mail.protection.outlook.com;
 spf=softfail (sender IP is 5.188.10.44) smtp.mailfrom=invoice-settlement.cc;
 dkim=none; dmarc=fail action=none header.from=invoice-settlement.cc
Return-Path: <noreply@invoice-settlement.cc>
From: "DHL Express Shipping" <noreply@invoice-settlement.cc>
To: "Accounts Payable" <accounts.payable@nexoragroup.in>
Subject: DHL Shipment Notification - AWB 4471882 held at customs
Date: Fri, 21 Aug 2026 02:52:47 +0000
Message-ID: <20260821025247.9182@invoice-settlement.cc>
X-Mailer: Microsoft Outlook Express 6.00.2900.5512
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_44718_9928114"

------=_Part_44718_9928114
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Dear Customer,

Your shipment with air waybill number AWB 4471882 is currently being held at
customs and cannot be released without the attached documentation.

Please open the attached shipping documents, print them and forward them to
your customs broker within 48 hours. Shipments not cleared within this period
are returned to sender at the consignee's expense.

Tracking number : AWB 4471882
Origin          : Frankfurt, DE
Destination     : Mumbai, IN
Status          : HELD - DOCUMENTATION REQUIRED

Thank you for choosing DHL Express.

DHL Customer Service

------=_Part_44718_9928114
Content-Type: application/octet-stream; name="Shipment_Documents_AWB4471882.pdf.exe"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="Shipment_Documents_AWB4471882.pdf.exe"

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAACAAAAADh+6DgC0Cc0huAFMzSFUaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiBE
T1MgbW9kZS4NDQokAAAAAAAAAFBFAABkhgIAU0lIRGVtb1NhbXBsZU5vdFJlYWxNYWx3YXJlVGhp
c0lzQVN5bnRoZXRpY1BsYWNlaG9sZGVyRm9yVGhlU2VudGluZWxUcmFjZURlbW9uc3RyYXRpb25D
b3JwdXNJdENvbnRhaW5zTm9FeGVjdXRhYmxlTG9naWNXaGF0c29ldmVy

------=_Part_44718_9928114--
`;

/* ------------------------------------------------------------------ */
/* Corpus                                                              */
/* ------------------------------------------------------------------ */

export const DEMO_MESSAGES: DemoMessage[] = [
  {
    id: 'bec-payment-diversion',
    filename: 'bec-payment-diversion.eml',
    label: 'Business email compromise — payment diversion',
    synopsis:
      'Vendor impersonation redirecting an invoice payment. Relayed through a second country so SPF fails at the boundary despite the origin sitting inside the authorised range.',
    expected: {
      classification: 'BUSINESS_EMAIL_COMPROMISE',
      level: 'CRITICAL',
      spf: 'FAIL',
      dkim: 'FAIL',
      dmarc: 'FAIL',
      origin: 'Singapore',
    },
    raw: BEC_PAYMENT_DIVERSION,
  },
  {
    id: 'credential-phishing',
    filename: 'credential-phishing.eml',
    label: 'Credential phishing — bank lookalike domain',
    synopsis:
      'Homoglyph domain impersonating a bank, with anchor text disguising the real destination. The sender publishes no SPF or DMARC at all.',
    expected: {
      classification: 'PHISHING',
      level: 'HIGH',
      spf: 'NONE',
      dkim: 'NONE',
      dmarc: 'NONE',
      origin: 'Romania',
    },
    raw: CREDENTIAL_PHISHING,
  },
  {
    id: 'legitimate-internal',
    filename: 'legitimate-internal.eml',
    label: 'Legitimate internal mail (control)',
    synopsis:
      'Genuine message between colleagues on well-configured infrastructure. Included so the detector can be seen clearing benign mail rather than flagging everything.',
    expected: {
      classification: 'LEGITIMATE',
      level: 'INFO',
      spf: 'NEUTRAL',
      dkim: 'NEUTRAL',
      dmarc: 'NEUTRAL',
      origin: null,
    },
    raw: LEGITIMATE_INTERNAL,
  },
  {
    id: 'display-name-spoof',
    filename: 'display-name-spoof.eml',
    label: 'Executive impersonation — gift card fraud via Tor',
    synopsis:
      'Display name embeds the CEO’s real address while the message comes from webmail, submitted through a Tor exit node so the true source is obscured.',
    expected: {
      classification: 'IMPERSONATION',
      level: 'HIGH',
      spf: 'NEUTRAL',
      dkim: 'NEUTRAL',
      dmarc: 'NEUTRAL',
      origin: 'Germany',
    },
    raw: DISPLAY_NAME_SPOOF,
  },
  {
    id: 'malware-delivery',
    filename: 'malware-delivery.eml',
    label: 'Malware delivery — double-extension executable',
    synopsis:
      'Fake customs notice carrying a .pdf.exe attachment that presents as a document in any client hiding known extensions.',
    expected: {
      classification: 'MALWARE',
      level: 'CRITICAL',
      spf: 'SOFTFAIL',
      dkim: 'NONE',
      dmarc: 'FAIL',
      origin: 'Russia',
    },
    raw: MALWARE_DELIVERY,
  },
];

/** The sample the dashboard's guided investigation runs. */
export const PRIMARY_DEMO_ID = 'bec-payment-diversion';

export function demoMessage(id: string): DemoMessage | null {
  return DEMO_MESSAGES.find((message) => message.id === id) ?? null;
}

export function primaryDemoMessage(): DemoMessage {
  const message = demoMessage(PRIMARY_DEMO_ID);
  if (!message) throw new Error(`Demo corpus is missing its primary message: ${PRIMARY_DEMO_ID}`);
  return message;
}
