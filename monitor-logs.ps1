Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object Windows.Forms.Form
$form.Text = 'Wi-Fi Pago - Monitor do servidor'
$form.Size = New-Object Drawing.Size(1000,650)
$form.StartPosition = 'CenterScreen'

$tabs = New-Object Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$form.Controls.Add($tabs)

$paths = @{
  'Backend' = 'C:\WifiPago\logs\backend-out.log'
  'Erros backend' = 'C:\WifiPago\logs\backend-error.log'
  'Caddy' = 'C:\caddy\logs\caddy.log'
}
$boxes = @{}
foreach($name in $paths.Keys){
  $page = New-Object Windows.Forms.TabPage
  $page.Text = $name
  $box = New-Object Windows.Forms.TextBox
  $box.Multiline = $true; $box.ReadOnly = $true; $box.ScrollBars = 'Both'; $box.WordWrap = $false
  $box.Dock = 'Fill'; $box.BackColor = [Drawing.Color]::FromArgb(20,25,35); $box.ForeColor = [Drawing.Color]::White
  $box.Font = New-Object Drawing.Font('Consolas',10)
  $page.Controls.Add($box); $tabs.TabPages.Add($page); $boxes[$name] = $box
}

$status = New-Object Windows.Forms.Label
$status.Dock = 'Bottom'; $status.Height = 28; $status.TextAlign = 'MiddleLeft'
$form.Controls.Add($status)

function Update-View {
  foreach($name in $paths.Keys){
    $file = $paths[$name]; $box = $boxes[$name]
    if(Test-Path $file){
      $text = Get-Content -LiteralPath $file -Tail 500 -ErrorAction SilentlyContinue | Out-String
      $box.Text = $text.TrimEnd()
      $box.SelectionStart = $box.TextLength; $box.ScrollToCaret()
    } else { $box.Text = "Arquivo ainda não existe:`r`n$file" }
  }
  $svc = (Get-Service WifiPagoBackend -ErrorAction SilentlyContinue).Status
  $caddy = (Get-Service Caddy -ErrorAction SilentlyContinue).Status
  $status.Text = "Backend: $svc    Caddy: $caddy    Atualizado: $(Get-Date -Format 'HH:mm:ss')"
}

$timer = New-Object Windows.Forms.Timer; $timer.Interval = 2000
$timer.Add_Tick({ Update-View }); $timer.Start()
$form.Add_Shown({ Update-View })
[Windows.Forms.Application]::Run($form)
