"""Pre-compiled multilingual scam-detection rules (English, Hindi, Hinglish, and Indic scripts)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class DetectionRule:
    rule_type: str
    cat_vote: str | None
    weight: int
    severity: str
    pattern: re.Pattern[str]
    exp_en: str
    exp_hi: str


CLIENT_RULES: Final[tuple[DetectionRule, ...]] = (
    DetectionRule(
        rule_type="urgency",
        cat_vote=None,
        weight=18,
        severity="medium",
        pattern=re.compile(
            r"\b(immediately|urgent|urgently|within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)|"
            r"tonight\s+at\s+[0-9:]+\s*(?:pm|am)?|today\s+at\s+[0-9:]+\s*(?:pm|am)?|"
            r"last\s+warning|final\s+notice|turant|abhi\s+ke\s+abhi|aaj\s+raat(?:\s+[0-9:]+\s*baje)?)\b|"
            r"तुरंत|अभी\s+के\s+अभी|आज\s+रात|अंतिम\s+चेतावनी|तत्काल",
            re.IGNORECASE,
        ),
        exp_en="Uses artificial urgency or a countdown deadline to pressure you into acting before verifying.",
        exp_hi="बिना जांच किए तुरंत कदम उठाने का दबाव बनाने के लिए कृत्रिम जल्दबाजी का उपयोग किया गया है।",
    ),
    DetectionRule(
        rule_type="impersonation",
        cat_vote="bank_impersonation",
        weight=32,
        severity="high",
        pattern=re.compile(
            r"\b(account\s+(?:and\s+\w+\s+access\s+)?(?:will\s+be\s+|has\s+been\s+|is\s+)?"
            r"(?:blocked|suspended|frozen|deactivated|closed)|card\s+(?:has\s+been\s+|will\s+be\s+)?blocked|"
            r"aapka\s+(?:[a-z]+\s+)?(?:bank\s+)?(?:account|khata)\s+(?:aaj\s+raat\s+)?"
            r"(?:block|band|suspend|freeze)\s+ho\s*(?:jayega|gaya\s+hai))\b|"
            r"खाता\s+(?:आज\s+रात\s+)?(?:ब्लॉक|बंद|सस्पेंड|फ्रीज)\s+हो\s+जाएगा|बैंक\s+खाता\s+(?:ब्लॉक|बंद|सस्पेंड)",
            re.IGNORECASE,
        ),
        exp_en="Threatens that your bank account or debit card is blocked or about to be suspended.",
        exp_hi="घबराहट पैदा करने के लिए आपके बैंक खाते या कार्ड के ब्लॉक/बंद होने की धमकी दी गई है।",
    ),
    DetectionRule(
        rule_type="impersonation",
        cat_vote="kyc_phishing",
        weight=34,
        severity="high",
        pattern=re.compile(
            r"\b(update\s+(?:your\s+|pan\s+)?(?:kyc|pan|aadhaar|aadhar)|"
            r"(?:kyc|pan\s+card(?:\s+kyc)?)\s+(?:has\s+|is\s+)?(?:expired|pending|incomplete|suspended|update\s+karo|update\s+karein)|"
            r"abhi\s+(?:apna\s+)?kyc\s+update\s+(?:karo|karein|kijiye))\b|"
            r"केवाईसी\s*(?:\(kyc\)\s*)?(?:अपडेट|लंबित|समाप्त|रद्द)|पैन\s+कार्ड\s+(?:और\s+केवाईसी\s+)?अपडेट",
            re.IGNORECASE,
        ),
        exp_en="Demands an urgent KYC, PAN, or Aadhaar update—one of the most common banking phishing lures.",
        exp_hi="तुरंत केवाईसी (KYC), पैन या आधार अपडेट करने की मांग की गई है।",
    ),
    DetectionRule(
        rule_type="credential_request",
        cat_vote="otp_credential_theft",
        weight=60,
        severity="high",
        pattern=re.compile(
            r"\b(share\s+(?:your\s+|the\s+|this\s+|6[\s-]digit\s+|cancellation\s+|apna\s+6\s+digit\s+)?"
            r"(?:otp|pin|cvv|password|mpin|passcode|code)|(?:6[\s-]digit\s+)?otp\s+share\s+(?:karo|karein|kijiye)|"
            r"otp\s+bhejo|reply\s+(?:with\s+)?(?:your\s+)?(?:otp|pin|cvv|password|mpin|passcode)|"
            r"send\s+(?:me\s+)?(?:your\s+)?(?:otp|pin|cvv|password|mpin|passcode)|"
            r"tell\s+(?:me\s+)?(?:your\s+)?(?:otp|pin|cvv|password|mpin|passcode)|"
            r"enter\s+(?:your\s+)?(?:atm\s+pin|cvv|netbanking\s+password)|share\s+otp\s+with\s+officer)\b|"
            r"ओटीपी\s*(?:\(otp\)\s*)?(?:और\s+एटीएम\s+पिन\s+|और\s+पासवर्ड\s+)?(?:तुरंत\s+)?(?:शेयर|साझा|बताएं|भेजें|दर्ज\s+करें)|पिन\s+शेयर\s+करें",
            re.IGNORECASE,
        ),
        exp_en="Asks you to share or enter an OTP, PIN, CVV, or password. Legitimate organizations never ask for these.",
        exp_hi="आपसे ओटीपी (OTP), पिन, सीवीवी या पासवर्ड साझा करने के लिए कहा गया है।",
    ),
    DetectionRule(
        rule_type="payment_request",
        cat_vote="upi_payment_scam",
        weight=48,
        severity="high",
        pattern=re.compile(
            r"\b(enter\s+(?:your\s+)?upi\s+pin|scan\s+(?:this\s+|the\s+)?qr\s*(?:code)?\s*"
            r"(?:and\s+enter\s+your\s+upi\s+pin|to\s+receive)|approve\s+(?:the\s+)?collect\s+request|"
            r"upi\s+pin\s+(?:dalein|dalo)|qr\s*(?:code\s+)?(?:google\s+pay\s+se\s+)?scan\s+karke)\b|"
            r"यूपीआई\s+पिन\s*(?:\(upi\s+pin\)\s*)?(?:डालें|दर्ज\s+करें)|क्यूआर\s*(?:\(qr\)\s*)?(?:कोड\s+)?(?:को\s+)?स्कैन\s+करें|कैशबैक\s+रिफंड\s+स्वीकृत",
            re.IGNORECASE,
        ),
        exp_en="Claims you must enter a UPI PIN or scan a QR code to receive money or cashback. UPI PIN is ONLY for sending money.",
        exp_hi="पैसा या रिफंड प्राप्त करने के लिए यूपीआई पिन डालने या क्यूआर कोड स्कैन करने का दावा किया गया है।",
    ),
    DetectionRule(
        rule_type="payment_request",
        cat_vote="job_scam",
        weight=42,
        severity="high",
        pattern=re.compile(
            r"\b(earn\s+(?:rs\.?|inr|₹)?\s*\d[\d,]*(?:\s+to\s+(?:rs\.?|inr|₹)?\s*\d[\d,]*)?\s*(?:per\s+day|daily|/day)|"
            r"part[\s-]time\s+(?:wfh\s+|work\s+from\s+home\s+)?(?:job|opportunity)|"
            r"(?:refundable\s+)?registration\s+fee\s+(?:bhejo|pay|deposit|today)|"
            r"liking\s+youtube\s+videos|rating\s+google\s+maps|roz\s+₹?\d+\s+kamayein)\b|"
            r"घर\s+बैठे\s+रोज़.*कमाएं|रजिस्ट्रेशन\s+फीस|प्रीपेड\s+टास्क",
            re.IGNORECASE,
        ),
        exp_en="Promotes high daily payouts for trivial online tasks or demands an upfront job registration fee.",
        exp_hi="आसान ऑनलाइन टास्क से रोज़ाना हजारों कमाने का प्रलोभन या पंजीकरण शुल्क मांगा गया है।",
    ),
    DetectionRule(
        rule_type="payment_request",
        cat_vote="prize_lottery_scam",
        weight=45,
        severity="high",
        pattern=re.compile(
            r"\b(won\s+(?:a\s+|₹[\d,]+\s+in\s+the\s+)?(?:lottery|lucky\s+draw|kbc|cash\s+prize)|"
            r"lucky\s+draw\s+mein.{0,35}lottery\s+jeeti|aapne.{0,25}lottery\s+jeeti\s+hai|"
            r"claim.{0,25}(?:lottery|prize))\b|"
            r"लॉटरी\s+जीती\s+है|लकी\s+ड्रॉ\s*(?:में|विजेता)|प्रोसेसिंग\s+फीस\s+जमा\s+करें|इनाम\s+पाने\s+के\s+लिए",
            re.IGNORECASE,
        ),
        exp_en="Claims you won an unexpected lottery, KBC prize, or lucky draw and asks for a fee to release winnings.",
        exp_hi="बिना किसी भागीदारी के लॉटरी, केबीसी या लकी ड्रॉ जीतने का दावा कर शुल्क मांगा गया है।",
    ),
    DetectionRule(
        rule_type="payment_request",
        cat_vote="scholarship_scam",
        weight=42,
        severity="high",
        pattern=re.compile(
            r"\b(scholarship\s+(?:grant|amount|approved).{0,65}(?:processing\s+fee|verification\s+charge|pay|claim)|"
            r"pay\s+₹?\d+\s+processing\s+fee.{0,40}disburse)\b|"
            r"छात्रवृत्ति\s+(?:योजना\s+के\s+तहत\s+)?.*स्वीकृत|छात्रवृत्ति.*शुल्क",
            re.IGNORECASE,
        ),
        exp_en="Lures students with an approved scholarship grant while demanding an upfront processing fee.",
        exp_hi="छात्रवृत्ति स्वीकृत होने का झांसा देकर प्रोसेसिंग शुल्क मांगा गया है।",
    ),
    DetectionRule(
        rule_type="impersonation",
        cat_vote="delivery_scam",
        weight=38,
        severity="high",
        pattern=re.compile(
            r"\b((?:parcel|package|shipment|delivery).{0,45}(?:incomplete|missing|invalid)\s+(?:house\s+|street\s+)?address|"
            r"update\s+delivery\s+address\s+within\s+\d+|redelivery\s+(?:fee|charge))\b|"
            r"पार्सल.*पता\s+अधूरा|पता\s+अधूरा\s+होने\s+के\s+कारण\s+आपका\s+पार्सल",
            re.IGNORECASE,
        ),
        exp_en="Claims a courier package is held due to an incomplete address and asks for a fee or unverified link click.",
        exp_hi="पता अधूरा होने के बहाने पार्सल रुकने का दावा कर बाहरी लिंक पर क्लिक करने को कहा गया है।",
    ),
    DetectionRule(
        rule_type="impersonation",
        cat_vote="government_impersonation",
        weight=46,
        severity="high",
        pattern=re.compile(
            r"\b(electricity\s+power\s+will\s+be\s+disconnected\s+tonight|previous\s+month\s+bill\s+was\s+not\s+updated|"
            r"digital\s+arrest|bijli\s+connection\s+aaj\s+raat\s+(?:[0-9:]+\s*baje\s+)?kat\s+jayega|"
            r"call\s+our\s+(?:electricity\s+)?officer\s+at\s+\d{10}|electricity\s+officer\s+ko\s+\d{10}\s+par\s+call)\b|"
            r"बिजली\s+कनेक्शन\s+आज\s+रात.*काट\s+दिया\s+जाएगा|डिजिटल\s+अरेस्ट|अवैध\s+कस्टम\s+पार्सल",
            re.IGNORECASE,
        ),
        exp_en="Impersonates an electricity utility or law enforcement officer ('Digital Arrest' / customs threat).",
        exp_hi="बिजली विभाग या पुलिस/कस्टम अधिकारी बनकर डराने और तुरंत संपर्क करने का दबाव बनाया गया है।",
    ),
    DetectionRule(
        rule_type="remote_access",
        cat_vote="tech_support_scam",
        weight=50,
        severity="high",
        pattern=re.compile(
            r"\b(anydesk|teamviewer|quicksupport|rustdesk|screen\s+sharing\s+app|"
            r"install\s+(?:this\s+)?(?:support\s+|apk\s+)?app|download\s+\S+\.apk)\b",
            re.IGNORECASE,
        ),
        exp_en="Asks you to install a remote-access app (AnyDesk/TeamViewer/QuickSupport) or sideload an APK.",
        exp_hi="रिमोट एक्सेस ऐप (AnyDesk/TeamViewer) या अनजान APK इंस्टॉल करने के लिए कहा गया है।",
    ),
    DetectionRule(
        rule_type="investment_lure",
        cat_vote="investment_scam",
        weight=44,
        severity="high",
        pattern=re.compile(
            r"\b(guaranteed\s+(?:daily\s+|weekly\s+|monthly\s+)?(?:returns?|profit)|"
            r"double\s+your\s+money|vip\s+(?:crypto|trading|stock)\s+(?:group|signal|tips)|"
            r"100%\s+risk[\s-]free\s+(?:profit|returns?))\b",
            re.IGNORECASE,
        ),
        exp_en="Promises guaranteed or risk-free trading/crypto returns—a classic investment fraud indicator.",
        exp_hi="बिना जोखिम गारंटीड मुनाफे या क्रिप्टो/ट्रेडिंग टिप्स का झांसा दिया गया है।",
    ),
    DetectionRule(
        rule_type="indic_scam",
        cat_vote="kyc_phishing",
        weight=38,
        severity="high",
        pattern=re.compile(
            r"કેવાયસી|ઓટીપી|ખાતું\s+બંધ|"
            r"வங்கி\s+கணக்கு|ஓடிபி|கேஒய்சி|"
            r"কেওয়াইসি|ওটিপি|ব্যাংক\s+অ্যাকাউন্ট\s+বন্ধ|"
            r"खाते\s+बंद\s+होईल|ओटीपी\s+शेअर",
            re.IGNORECASE,
        ),
        exp_en="Matches an Indic-language banking/KYC/OTP scam pattern (Gujarati, Tamil, Bengali, or Marathi).",
        exp_hi="क्षेत्रीय भारतीय भाषा (गुजराती, तमिल, बंगाली या मराठी) में केवाईसी/ओटीपी स्कैम संकेत मिला है।",
    ),
)

SAFE_OTP_NOTICE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(?:never|do\s+not|don't)\s+share\s+(?:your\s+|this\s+)?(?:otp|pin|cvv|password)\b|"
    r"कभी\s+(?:भी\s+)?(?:ओटीपी|otp|पिन)\s+(?:शेयर|साझा)\s+न\s+करें",
    re.IGNORECASE,
)

OTP_CODE_MENTION_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(?:your\s+)?(?:otp|one[\s-]time\s+password)\s+(?:for\s+.{1,40}\s+)?is\s+\d{4,8}\b",
    re.IGNORECASE,
)
