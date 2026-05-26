document.addEventListener('click', function (event) {
  var closeButton = event.target.closest('[data-bs-dismiss="alert"]');
  if (!closeButton) {
    return;
  }

  var alert = closeButton.closest('.alert');
  if (alert) {
    alert.remove();
  }
});
