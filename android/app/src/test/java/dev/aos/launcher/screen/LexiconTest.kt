package dev.aos.launcher.screen

import dev.aos.launcher.capabilities.Risk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LexiconTest {
    private fun button(label: String) =
        Element(1, "android.widget.Button", label, "", "", true, false, false, null, false, 0, 0, 1, 1)

    @Test fun irreversibleButtonsInManyLanguages() {
        for (label in listOf("Löschen", "Jetzt kaufen", "Supprimer", "Eliminar", "Elimina", "Excluir", "Verwijderen",
            "Usuń", "Sil", "Ta bort", "Удалить", "Видалити", "מחק", "حذف", "हटाएं", "删除", "刪除", "削除", "삭제",
            "Senden", "Envoyer", "Отправить", "שלח", "إرسال", "发送", "送信", "보내기", "Bezahlen", "결제")) {
            assertNotNull(label, Lexicon.irreversible(label))
            assertEquals(label, Risk.IRREVERSIBLE, ScreenRules.assess("tap", button(label), "x").risk)
        }
    }

    @Test fun wholeWordsOnlyForSpacedLanguages() {
        // "Anmelden" = sign in (not "melden" = report); "Silent" isn't Turkish "sil"; "Mitteilungen" isn't "teilen".
        for (label in listOf("Anmelden", "Silent mode", "Mitteilungen", "Weiter", "Einstellungen", "Sender settings",
            "Ringtone", "Delegate", "Stopwatch", "Alarme", "Inbox")) {
            assertNull(label, Lexicon.irreversible(label))
        }
    }

    @Test fun protectedControlsInManyLanguages() {
        for (label in listOf("Auf Werkseinstellungen zurücksetzen", "Entwickleroptionen", "Options de développement",
            "Opciones de desarrollador", "Сброс к заводским настройкам", "개발자 옵션", "开发者选项", "緊急通報", "Bedienungshilfen")) {
            assertNotNull(label, ScreenRules.assess("tap", button(label), "com.android.settings").forbidden)
        }
        // Everyday verbs are not protected controls (only asked about, if at all).
        for (label in listOf("Schließen", "Kapat", "Apagar", "Ausschalten", "Restablecer", "Reset")) {
            assertNull(label, ScreenRules.assess("tap", button(label), "x").forbidden)
        }
    }

    @Test fun uncoveredPhoneLanguageMakesEveryNamedTapAsk() {
        // Finnish isn't covered: "Poista" (delete) can't be recognised, so every tap asks.
        val fi = ScreenRules.assess("tap", button("Poista"), "x", phoneLanguage = "fi")
        assertEquals(Risk.IRREVERSIBLE, fi.risk)
        assertTrue(fi.reason, fi.reason.contains("can't judge buttons"))
        // Covered languages: ordinary taps still run.
        assertEquals(Risk.REVERSIBLE, ScreenRules.assess("tap", button("Weiter"), "x", phoneLanguage = "de").risk)
        assertEquals(Risk.REVERSIBLE, ScreenRules.assess("tap", button("Stopwatch"), "x", phoneLanguage = "en").risk)
        // Scrolling and Back don't depend on reading buttons.
        assertEquals(Risk.NONE, ScreenRules.assess("scroll", null, "x", phoneLanguage = "fi").risk)
    }

    @Test fun everyLanguageHasBothLists() {
        assertEquals(Lexicon.IRREVERSIBLE.keys, Lexicon.CORE_SURFACE.keys)
        assertTrue(Lexicon.COVERED.containsAll(listOf("en", "de", "ko", "he", "zh", "ja")))
    }
}
