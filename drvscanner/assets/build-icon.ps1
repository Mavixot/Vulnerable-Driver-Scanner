$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$entries = @()
foreach ($size in @(16, 24, 32, 48, 64, 256)) {
    $bitmap = [Drawing.Bitmap]::new($size, $size)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.ScaleTransform($size / 64.0, $size / 64.0)
    $background = [Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(37, 99, 235))
    $shape = [Drawing.Drawing2D.GraphicsPath]::new()
    foreach ($arc in @(@(0,0,180), @(36,0,270), @(36,36,0), @(0,36,90))) {
        $shape.AddArc($arc[0], $arc[1], 28, 28, $arc[2], 90)
    }
    $shape.CloseFigure()
    $graphics.FillPath($background, $shape)
    $pen = [Drawing.Pen]::new([Drawing.Color]::White, 3)
    $graphics.DrawRectangle($pen, 18, 18, 28, 28)
    foreach ($line in @(@(25,26,39,26), @(25,32,34,32), @(25,38,39,38))) {
        $graphics.DrawLine($pen, $line[0], $line[1], $line[2], $line[3])
    }
    foreach ($position in @(24,32,40)) {
        $graphics.DrawLine($pen, 12,$position,18,$position)
        $graphics.DrawLine($pen, 46,$position,52,$position)
        $graphics.DrawLine($pen, $position,12,$position,18)
        $graphics.DrawLine($pen, $position,46,$position,52)
    }
    $memory = [IO.MemoryStream]::new()
    $bitmap.Save($memory, [Drawing.Imaging.ImageFormat]::Png)
    $entries += ,@($size, $memory.ToArray())
    $memory.Dispose(); $pen.Dispose(); $shape.Dispose(); $background.Dispose(); $graphics.Dispose(); $bitmap.Dispose()
}
$file = [IO.File]::Create((Join-Path $PSScriptRoot 'driver-scanner.ico'))
$writer = [IO.BinaryWriter]::new($file)
try {
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$entries.Count)
    $offset = 6 + 16 * $entries.Count
    foreach ($entry in $entries) {
        $dimension = if ($entry[0] -eq 256) { 0 } else { $entry[0] }
        $writer.Write([byte]$dimension); $writer.Write([byte]$dimension)
        $writer.Write([byte]0); $writer.Write([byte]0)
        $writer.Write([uint16]1); $writer.Write([uint16]32)
        $writer.Write([uint32]$entry[1].Length); $writer.Write([uint32]$offset)
        $offset += $entry[1].Length
    }
    foreach ($entry in $entries) { $writer.Write([byte[]]$entry[1]) }
} finally { $writer.Dispose(); $file.Dispose() }
