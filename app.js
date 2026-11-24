document.addEventListener("DOMContentLoaded", () => {
  if ("serviceWorker" in navigator && window.location.protocol !== "file:") {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }
  const speakBtn = document.getElementById("btn-read-aloud");
  if (speakBtn && "speechSynthesis" in window) {
    speakBtn.addEventListener("click", () => {
      const text = speakBtn.dataset.speechText || "";
      const lang = speakBtn.dataset.speechLang || "en-IN";
      if (!text) return;
      window.speechSynthesis.cancel();
      const utter = new SpeechSynthesisUtterance(text);
      utter.lang = lang;
      window.speechSynthesis.speak(utter);
    });
  }
});
