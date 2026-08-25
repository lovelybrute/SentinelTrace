/**
 * The canonical SIH demo email.
 *
 * A realistic Business Email Compromise scenario — a fake finance department
 * email requesting an urgent bank-account change. This produces a CRITICAL
 * verdict with all key forensic signals when analysed.
 */

export const DEMO_EMAIL_RAW = `Received: from mail-sg-smtp-1.example.net (mail-sg-smtp-1.example.net [203.0.113.24])
        by mx.targetcorp.in (Postfix) with ESMTP id 4A2F18D3C1
        for <finance@targetcorp.in>; Mon, 25 Aug 2026 08:31:14 +0530 (IST)
Received: from smtp-relay.protonmail.ch (smtp-relay.protonmail.ch [185.220.101.45])
        by mail-sg-smtp-1.example.net (Postfix) with ESMTPS id 3B1E7A91F0
        for <finance@targetcorp.in>; Mon, 25 Aug 2026 03:01:09 +0000 (UTC)
Received: from [10.0.0.1] (unknown [77.88.5.12])
        by smtp-relay.protonmail.ch with HTTPS id smb8a4ac2bea7f45a2
        Mon, 25 Aug 2026 03:01:07 +0000 (UTC)
Authentication-Results: mx.targetcorp.in;
        spf=fail (mx.targetcorp.in: domain of cfo@acmecorp.com does not designate 203.0.113.24 as permitted sender) smtp.mailfrom=cfo@acmecorp.com;
        dkim=none (no signature);
        dmarc=fail (p=reject) header.from=acmecorp.com
From: "Rajiv Sharma - CFO, ACME Corp" <cfo@acmecorp.com>
To: <finance@targetcorp.in>
Reply-To: reply-acme-finance@protonmail.com
Return-Path: bounce@paypa1-security.com
Subject: URGENT: Vendor Bank Account Change — Action Required Today
Date: Mon, 25 Aug 2026 08:31:05 +0530
Message-ID: <20260825030107.smb8a4ac2b@paypa1-security.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Mailer: SendGrid v6.4.2
X-Originating-IP: 203.0.113.24

Dear Finance Team,

I hope this message finds you well. I am writing to you on an extremely urgent matter that requires your immediate attention and action today.

Our long-standing vendor, Global Tech Supplies Pvt. Ltd., has notified us that their bank account details have changed with immediate effect. All outstanding and future payments must be directed to the new account to avoid any disruption in supply.

Please update your records and process the following pending invoice immediately:

    Vendor: Global Tech Supplies Pvt. Ltd.
    Invoice No.: GTS-INV-2026-4471
    Amount: INR 47,00,000 (Forty-Seven Lakh Only)
    New Bank Account: HDFC Bank
    Account No.: 50200098765432
    IFSC Code: HDFC0001234

This change has been verified and approved at the Board level. Please process this transfer by 3:00 PM today to avoid penalty charges as per our vendor agreement.

Do NOT use the old account — any payment to the previous account will be lost and cannot be recovered.

For verification, please click the link below and confirm your action:
https://paypa1-security.com/verify-payment?token=3f8a9b2c1d4e5f6a7b8c9d0e1f2a3b4c&redirect=payment-confirm

If you have any questions, please reply to this email directly. Do not call the main office line as I am currently in a Board meeting.

Regards,

Rajiv Sharma
Chief Financial Officer
ACME Corporation
Mobile: +91 98765 43210 (For urgent matters only)

CONFIDENTIAL: This email and any attachments are for the exclusive and confidential use of the intended recipient. If you are not the intended recipient, please do not read, distribute or take action in reliance upon this message.`;

export const DEMO_EMAIL_FILENAME = 'acmecorp-cfo-urgent-payment.eml';

export const DEMO_SCENARIO = {
  title: 'BEC Demo: Fake CFO Invoice Redirect',
  expectedClassification: 'BUSINESS_EMAIL_COMPROMISE',
  expectedScore: 87,
  keyFindings: [
    'Executive impersonation (CFO of ACME Corp)',
    'Lookalike domain: paypa1-security.com ≈ paypal.com',
    'Reply-To mismatch: protonmail address',
    'Return-Path via malicious domain',
    'SPF FAIL, DKIM missing, DMARC FAIL',
    'Urgency language: "today", "penalty", "do not call"',
    'Payment diversion request: ₹47 lakh',
    'Suspicious URL with token parameter',
    'Multi-hop relay through Singapore → Germany',
  ],
};
