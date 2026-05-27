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
      var chartItems;
      if (canvas.dataset.chartType === 'quarantine') {
        chartItems = [
          { label: 'Quarantined', value: Number(canvas.dataset.quarantined || 0), color: '#35b7ff' },
          { label: 'Released/Clear', value: Number(canvas.dataset.released || 0), color: '#35d39f' }
        ];
      } else {
        chartItems = [
          { label: 'Safe', value: Number(canvas.dataset.safe || 0), color: '#35d39f' },
          { label: 'Suspicious', value: Number(canvas.dataset.suspicious || 0), color: '#ffc857' },
          { label: 'Phishing', value: Number(canvas.dataset.phishing || 0), color: '#ff4d67' },
          { label: 'Quarantined', value: Number(canvas.dataset.quarantined || 0), color: '#35b7ff' }
        ];
      }
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

    document.querySelectorAll('.calendar-chart').forEach(function (canvas) {
      function readSeries(range) {
        return {
          labels: JSON.parse(canvas.dataset[range + 'Labels'] || '[]'),
          values: JSON.parse(canvas.dataset[range + 'Values'] || '[]')
        };
      }

      var currentRange = 'day';
      var currentSeries = readSeries(currentRange);
      var calendarChart = new Chart(canvas, {
        type: 'bar',
        data: {
          labels: currentSeries.labels,
          datasets: [{
            label: 'Scans',
            data: currentSeries.values,
            backgroundColor: 'rgba(53, 183, 255, 0.72)',
            borderColor: '#35b7ff',
            borderWidth: 1,
            borderRadius: 8
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              ticks: { color: '#cfe3f8' },
              grid: { color: 'rgba(148, 163, 184, 0.12)' }
            },
            y: {
              beginAtZero: true,
              ticks: { color: '#cfe3f8', precision: 0 },
              grid: { color: 'rgba(148, 163, 184, 0.12)' }
            }
          },
          plugins: {
            legend: {
              labels: { color: '#cfe3f8' }
            },
            tooltip: {
              callbacks: {
                label: function (context) {
                  return 'Scans: ' + context.parsed.y;
                }
              }
            }
          }
        }
      });

      document.querySelectorAll('[data-calendar-controls="' + canvas.id + '"] [data-calendar-range]').forEach(function (button) {
        button.addEventListener('click', function () {
          currentRange = button.dataset.calendarRange;
          currentSeries = readSeries(currentRange);
          calendarChart.data.labels = currentSeries.labels;
          calendarChart.data.datasets[0].data = currentSeries.values;
          calendarChart.update();

          button.parentElement.querySelectorAll('button').forEach(function (otherButton) {
            otherButton.classList.toggle('active', otherButton === button);
          });
        });
      });
    });
  }

  document.querySelectorAll('.calendar-heatmap').forEach(function (calendar) {
    var cells = JSON.parse(calendar.dataset.cells || '[]');
    var months = JSON.parse(calendar.dataset.months || '[]');
    var maxWeek = cells.reduce(function (largestWeek, cell) {
      return Math.max(largestWeek, cell.week || 0);
    }, 0);
    var weekCount = maxWeek + 1;
    var weekdayNames = ['M', 'T', 'W', 'T', 'F', 'S', 'S'];

    var monthRow = document.createElement('div');
    monthRow.className = 'calendar-months';
    monthRow.style.gridTemplateColumns = '34px repeat(' + weekCount + ', 18px)';

    var monthSpacer = document.createElement('span');
    monthRow.appendChild(monthSpacer);

    months.forEach(function (month) {
      var monthLabel = document.createElement('span');
      monthLabel.textContent = month.label;
      monthLabel.style.gridColumn = (month.week + 2) + ' / span 4';
      monthRow.appendChild(monthLabel);
    });

    var grid = document.createElement('div');
    grid.className = 'calendar-grid';
    grid.style.gridTemplateColumns = '34px repeat(' + weekCount + ', 18px)';

    weekdayNames.forEach(function (weekdayName, index) {
      var weekday = document.createElement('span');
      weekday.className = 'calendar-weekday';
      weekday.textContent = weekdayName;
      weekday.style.gridColumn = '1';
      weekday.style.gridRow = String(index + 1);
      grid.appendChild(weekday);
    });

    cells.forEach(function (cell) {
      var day = document.createElement('span');
      day.className = 'calendar-cell level-' + cell.level;
      day.title = cell.label + ': ' + cell.count + ' scan' + (cell.count === 1 ? '' : 's');
      day.style.gridColumn = String(cell.week + 2);
      day.style.gridRow = String(cell.weekday + 1);
      grid.appendChild(day);
    });

    var legend = document.createElement('div');
    legend.className = 'calendar-legend';
    legend.innerHTML = '<span>Less</span><i class="level-0"></i><i class="level-1"></i><i class="level-2"></i><i class="level-3"></i><i class="level-4"></i><span>More</span>';

    calendar.replaceChildren(monthRow, grid, legend);
  });
});
