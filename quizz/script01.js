
document.addEventListener("DOMContentLoaded", function () {
  const botao = document.getElementById("verificar");
  if (botao) {
    botao.addEventListener("click", function () {
      const nome = document.getElementById("nome").value.trim();
      if (nome.length < 5) {
        alert("Por favor, digite seu nome completo.");
        return;
      }
      const valor = (Math.floor(Math.random() * (7000 - 2000 + 1)) + 2000)
                      .toLocaleString('pt-BR', { minimumFractionDigits: 2 });
      const mensagem = `${nome}, encontramos R$${valor} em reembolso disponível para seu CPF.`;
      document.getElementById("mensagem").textContent = mensagem;
      document.getElementById("resultadoBox").classList.remove("hidden");
    });
  }
});
