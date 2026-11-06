package dev.aos.launcher.screen

import java.util.Locale

/**
 * Words that mark a control as irreversible (send, pay, delete...) or as a protected system
 * surface (factory reset...), in the languages Agent Do/Don't can judge. Every language is checked on every
 * screen, because an app's language can differ from the phone's. Pure Kotlin, unit-tested.
 *
 * Space-separated languages match whole words, so "anmelden" (sign in) doesn't match "melden"
 * (report). Scripts that attach particles or don't use spaces (Hebrew, Arabic, Hindi, Chinese,
 * Japanese, Korean) and the Cyrillic stems match as substrings: a wrong match only means an extra
 * question, never a missed one.
 *
 * When the phone's language isn't covered here, the policy asks before every tap
 * ([ScreenRules.assess] with languageCovered = false).
 */
object Lexicon {
    val IRREVERSIBLE: Map<String, List<String>> = mapOf(
        "en" to listOf(
            "send", "pay", "buy", "purchase", "order", "checkout", "check out", "delete", "remove", "uninstall",
            "install", "erase", "transfer", "subscribe", "unsubscribe", "post", "publish", "share", "call", "dial",
            "accept", "agree", "submit", "sign out", "log out", "logout", "format", "discard", "clear data",
            "clear storage", "clear cache", "block", "report", "forward", "confirm", "donate", "book", "reserve",
            "move to trash", "empty trash",
        ),
        "de" to listOf(
            "senden", "absenden", "bezahlen", "zahlen", "kaufen", "jetzt kaufen", "bestellen", "löschen", "entfernen",
            "deinstallieren", "installieren", "überweisen", "abonnieren", "kündigen", "posten", "veröffentlichen",
            "teilen", "anrufen", "akzeptieren", "zustimmen", "bestätigen", "abmelden", "ausloggen", "verwerfen",
            "blockieren", "melden", "weiterleiten", "spenden", "buchen", "reservieren", "in den papierkorb",
        ),
        "fr" to listOf(
            "envoyer", "payer", "acheter", "commander", "supprimer", "effacer", "retirer", "désinstaller", "installer",
            "virement", "transférer", "s'abonner", "se désabonner", "publier", "partager", "appeler", "accepter",
            "confirmer", "valider", "se déconnecter", "déconnexion", "bloquer", "signaler", "faire un don", "réserver",
            "mettre à la corbeille",
        ),
        "es" to listOf(
            "enviar", "pagar", "comprar", "realizar pedido", "eliminar", "borrar", "quitar", "desinstalar", "instalar",
            "transferir", "suscribirse", "publicar", "compartir", "llamar", "aceptar", "confirmar", "cerrar sesión",
            "descartar", "bloquear", "denunciar", "reenviar", "donar", "reservar", "mover a la papelera",
        ),
        "it" to listOf(
            "invia", "inviare", "paga", "pagare", "acquista", "compra", "ordina", "elimina", "cancella", "rimuovi",
            "disinstalla", "installa", "trasferisci", "bonifico", "iscriviti", "abbonati", "pubblica", "condividi",
            "chiama", "accetta", "conferma", "disconnetti", "scarta", "blocca", "segnala", "inoltra", "dona", "prenota",
        ),
        "pt" to listOf(
            "enviar", "pagar", "comprar", "excluir", "apagar", "remover", "desinstalar", "instalar", "transferir",
            "assinar", "inscrever-se", "publicar", "postar", "compartilhar", "partilhar", "aceitar", "confirmar",
            "terminar sessão", "descartar", "bloquear", "denunciar", "encaminhar", "doar", "reservar",
        ),
        "nl" to listOf(
            "verzenden", "versturen", "betalen", "kopen", "bestellen", "verwijderen", "wissen", "installeren",
            "overmaken", "abonneren", "publiceren", "posten", "delen", "bellen", "accepteren", "akkoord", "bevestigen",
            "afmelden", "uitloggen", "weggooien", "blokkeren", "rapporteren", "doorsturen", "doneren", "boeken",
            "reserveren",
        ),
        "pl" to listOf(
            "wyślij", "zapłać", "kup", "kupuję", "zamów", "usuń", "odinstaluj", "zainstaluj", "przelew", "subskrybuj",
            "opublikuj", "udostępnij", "zadzwoń", "akceptuj", "zaakceptuj", "potwierdź", "wyloguj", "odrzuć",
            "zablokuj", "zgłoś", "przekaż", "zarezerwuj",
        ),
        "tr" to listOf(
            "gönder", "öde", "ödeme yap", "satın al", "sipariş ver", "sil", "kaldır", "yükle", "havale", "abone ol",
            "paylaş", "yayınla", "kabul et", "onayla", "çıkış yap", "oturumu kapat", "engelle", "bildir", "ilet",
            "bağış yap", "rezervasyon yap",
        ),
        "sv" to listOf(
            "skicka", "betala", "köp", "beställ", "ta bort", "radera", "avinstallera", "installera", "överför",
            "prenumerera", "publicera", "dela", "ring", "acceptera", "godkänn", "bekräfta", "logga ut", "släng",
            "blockera", "rapportera", "vidarebefordra", "donera", "boka", "reservera",
        ),
        "ru" to listOf(
            "отправ", "оплат", "купить", "заказ", "удал", "стереть", "установ", "перевод", "перевести", "подпис",
            "опубликов", "поделит", "позвон", "принять", "подтверд", "выйти", "заблок", "пожалов", "пересла",
            "пожертв", "заброн",
        ),
        "uk" to listOf(
            "надісл", "оплат", "купити", "замов", "видал", "встанов", "переказ", "підпис", "опублік", "поділит",
            "зателефон", "прийняти", "підтверд", "вийти", "заблок", "поскарж", "пересла", "заброн",
        ),
        "he" to listOf(
            "שלח", "שליחה", "שלם", "תשלום", "קנה", "קנייה", "רכישה", "הזמן", "מחק", "מחיקה", "הסר", "הסרה", "התקן",
            "העבר", "הירשם", "פרסם", "שתף", "התקשר", "חייג", "אשר", "אישור", "מסכים", "התנתק", "חסום", "דווח", "תרום",
        ),
        "ar" to listOf(
            "إرسال", "ارسال", "أرسل", "دفع", "ادفع", "شراء", "اشتر", "اطلب", "حذف", "احذف", "إزالة", "ازالة", "تثبيت",
            "تحويل", "اشتراك", "اشترك", "نشر", "انشر", "مشاركة", "شارك", "اتصال", "اتصل", "قبول", "أوافق", "موافق",
            "تأكيد", "أكد", "تسجيل الخروج", "حظر", "إبلاغ", "إعادة توجيه", "تبرع", "حجز", "احجز",
        ),
        "hi" to listOf(
            "भेजें", "भेजना", "भुगतान", "खरीदें", "ऑर्डर", "हटाएं", "हटाएँ", "मिटाएं", "अनइंस्टॉल", "इंस्टॉल", "ट्रांसफ़र",
            "सदस्यता", "पोस्ट", "शेयर", "कॉल", "स्वीकार", "सहमत", "पुष्टि", "साइन आउट", "लॉग आउट", "ब्लॉक", "रिपोर्ट",
            "फ़ॉरवर्ड", "दान", "बुक",
        ),
        "zh" to listOf(
            "发送", "發送", "支付", "付款", "购买", "購買", "下单", "下單", "删除", "刪除", "移除", "卸载", "解除安裝", "安装",
            "安裝", "转账", "轉帳", "订阅", "訂閱", "发布", "發佈", "分享", "呼叫", "拨打", "撥打", "接受", "同意", "确认",
            "確認", "提交", "退出登录", "登出", "丢弃", "舍弃", "屏蔽", "封锁", "封鎖", "举报", "檢舉", "转发", "轉寄", "捐款",
            "预订", "預訂",
        ),
        "ja" to listOf(
            "送信", "支払", "購入", "注文", "削除", "消去", "アンインストール", "インストール", "振込", "送金", "投稿", "共有",
            "発信", "承認", "同意", "確定", "ログアウト", "破棄", "ブロック", "報告", "転送", "寄付", "予約",
        ),
        "ko" to listOf(
            "보내기", "전송", "결제", "지불", "구매", "주문", "삭제", "제거", "설치", "송금", "이체", "구독", "게시", "공유",
            "전화", "통화", "수락", "동의", "로그아웃", "버리기", "차단", "신고", "전달", "기부", "예약",
        ),
    )

    /** Controls the agent never presses: factory reset, developer options, emergency, accessibility. */
    val CORE_SURFACE: Map<String, List<String>> = mapOf(
        "en" to listOf("factory data reset", "factory reset", "reset phone", "erase all", "emergency call",
            "emergency sos", "emergency", "usb debugging", "developer options", "find my mobile", "lock phone",
            "power off", "restart", "accessibility"),
        "de" to listOf("auf werkseinstellungen zurücksetzen", "werkseinstellungen", "notruf", "notfall",
            "entwickleroptionen", "usb-debugging", "bedienungshilfen", "neu starten"),
        "fr" to listOf("réinitialisation des données d'usine", "appel d'urgence", "urgence",
            "options de développement", "options pour les développeurs", "débogage usb", "accessibilité", "redémarrer"),
        "es" to listOf("restablecer datos de fábrica", "llamada de emergencia", "emergencia",
            "opciones de desarrollador", "depuración usb", "accesibilidad", "reiniciar"),
        "it" to listOf("ripristino dati di fabbrica", "chiamata di emergenza", "emergenza",
            "opzioni sviluppatore", "debug usb", "accessibilità", "riavvia"),
        "pt" to listOf("redefinição para dados de fábrica", "restaurar padrão de fábrica", "chamada de emergência",
            "emergência", "opções do programador", "opções do desenvolvedor", "depuração usb", "acessibilidade", "reiniciar"),
        "nl" to listOf("fabrieksinstellingen", "noodoproep", "noodgeval", "ontwikkelaarsopties", "usb-foutopsporing",
            "toegankelijkheid", "opnieuw opstarten"),
        "pl" to listOf("ustawienia fabryczne", "połączenie alarmowe", "alarmowe", "opcje programisty",
            "debugowanie usb", "ułatwienia dostępu", "uruchom ponownie"),
        "tr" to listOf("fabrika ayarlarına sıfırla", "fabrika verilerine sıfırla", "acil arama", "acil durum",
            "geliştirici seçenekleri", "usb hata ayıklama", "erişilebilirlik", "yeniden başlat"),
        "sv" to listOf("fabriksåterställning", "nödsamtal", "nödläge", "utvecklaralternativ",
            "usb-felsökning", "tillgänglighet", "starta om"),
        "ru" to listOf( "заводск", "экстренн", "параметры разработчика", "отладка по usb", "специальные возможности", "перезагруз"),
        "uk" to listOf( "заводськ", "екстрен", "параметри розробника", "налагодження usb", "спеціальні можливості", "перезавант"),
        "he" to listOf( "חירום", "אפשרויות מפתחים", "ניפוי באגים", "נגישות", "הפעלה מחדש"),
        "ar" to listOf("ضبط المصنع", "طوارئ", "خيارات المطور", "تصحيح أخطاء usb", "إمكانية الوصول", "إعادة التشغيل"),
        "hi" to listOf("फ़ैक्टरी", "आपातकालीन", "डेवलपर विकल्प", "यूएसबी डीबगिंग", "सुलभता", "रीस्टार्ट"),
        "zh" to listOf("恢复出厂", "恢復原廠", "紧急", "緊急", "开发者选项", "開發人員選項", "usb 调试", "USB 偵錯", "无障碍",
            "無障礙", "关机", "關機", "重启", "重新啟動"),
        "ja" to listOf( "工場出荷", "緊急", "開発者向けオプション", "usbデバッグ", "ユーザー補助", "アクセシビリティ",
            "電源を切る", "再起動"),
        "ko" to listOf( "공장 데이터", "긴급", "개발자 옵션", "usb 디버깅", "접근성", "전원 끄기", "다시 시작"),
    )

    /** Languages whose words are matched whole (space-separated scripts); the rest match as substrings. */
    private val WHOLE_WORDS = setOf("en", "de", "fr", "es", "it", "pt", "nl", "pl", "tr", "sv")

    val COVERED: Set<String> = IRREVERSIBLE.keys

    data class Hit(val language: String, val word: String)

    private class Matcher(table: Map<String, List<String>>) {
        private val whole = table.filterKeys { it in WHOLE_WORDS }.flatMap { (lang, ws) -> ws.map { lang to it } }
        private val substr = table.filterKeys { it !in WHOLE_WORDS }.flatMap { (lang, ws) -> ws.map { lang to it.lowercase(Locale.ROOT) } }
        private val wholeRegex = Regex(
            "(?<!\\p{L})(" + whole.map { it.second }.distinct().sortedByDescending { it.length }
                .joinToString("|") { Regex.escape(it.lowercase(Locale.ROOT)).replace(" ", "\\E[\\s_\\-]+\\Q") } + ")(?!\\p{L})",
        )
        private val wordLang = whole.associate { it.second.lowercase(Locale.ROOT) to it.first }

        fun find(text: String): Hit? {
            val t = text.lowercase(Locale.ROOT)
            wholeRegex.find(t)?.let { m ->
                val w = m.value.replace(Regex("[\\s_\\-]+"), " ")
                return Hit(wordLang[w] ?: "?", m.value)
            }
            return substr.firstOrNull { (_, w) -> t.contains(w) }?.let { Hit(it.first, it.second) }
        }
    }

    private val irreversible = Matcher(IRREVERSIBLE)
    private val coreSurface = Matcher(CORE_SURFACE)

    fun irreversible(text: String): Hit? = irreversible.find(text)
    fun coreSurface(text: String): Hit? = coreSurface.find(text)
}
