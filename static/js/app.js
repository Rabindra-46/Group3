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

document.addEventListener('DOMContentLoaded', function () {
  var sampleButton = document.querySelector('[data-sample-email]');
  var rawEmail = document.querySelector('#raw_email');
  if (sampleButton && rawEmail) {
    sampleButton.addEventListener('click', function () {
      rawEmail.value = [
        'From: PayPal Security <notice@random-example.xyz>',
        'Reply-To: support@secure-billing-alert.xyz',
        'Return-Path: <bounce@unknown-mailer.xyz>',
        'Subject: Urgent verify now - account suspended',
        'Authentication-Results: spf=fail smtp.mailfrom=unknown-mailer.xyz; dkim=fail; dmarc=fail',
        'MIME-Version: 1.0',
        'Content-Type: text/html; charset="UTF-8"',
        '',
        '<html>',
        '  <body>',
        '    <h2>Account suspended</h2>',
        '    <p>Dear customer, your PayPal account has been suspended.</p>',
        '    <p>Immediate action is required. Verify now to avoid limited access.</p>',
        '    <p><a href="http://bit.ly/login-update">Verify your account</a></p>',
        '    <p>Please confirm your password and credit card details.</p>',
        '  </body>',
        '</html>'
      ].join('\n');
      rawEmail.focus();
    });
  }

  if (window.Chart) {
    document.querySelectorAll('.soc-chart').forEach(function (canvas) {
      var chartItems = [
        { label: 'Safe', value: Number(canvas.dataset.safe || 0), color: '#35d39f' },
        { label: 'Suspicious', value: Number(canvas.dataset.suspicious || 0), color: '#ffc857' },
        { label: 'Phishing', value: Number(canvas.dataset.phishing || 0), color: '#ff4d67' },
        { label: 'Quarantined', value: Number(canvas.dataset.quarantined || 0), color: '#35b7ff' }
      ];
      var total = chartItems.reduce(function (sum, item) {
        return sum + item.value;
      }, 0);
      var visibleItems = chartItems.filter(function (item) {
        return item.value > 0;
      });

      if (!visibleItems.length) {
        visibleItems = [{ label: 'No scans yet', value: 1, color: '#334155' }];
      }

      new Chart(canvas, {
        type: 'doughnut',
        data: {
          labels: visibleItems.map(function (item) {
            return item.label;
          }),
          datasets: [{
            data: visibleItems.map(function (item) {
              return item.value;
            }),
            backgroundColor: visibleItems.map(function (item) {
              return item.color;
            }),
            borderColor: '#07111f',
            borderWidth: 3,
            hoverOffset: 8
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: '#cfe3f8',
                boxWidth: 14,
                padding: 16
              }
            },
            tooltip: {
              callbacks: {
                label: function (context) {
                  if (!total) {
                    return 'No scans yet';
                  }
                  var value = context.parsed;
                  var percent = Math.round((value / total) * 100);
                  return context.label + ': ' + value + ' (' + percent + '%)';
                }
              }
            }
          },
          cutout: '62%'
        }
      });
    });
  }
});
