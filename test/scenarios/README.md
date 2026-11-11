Build CLI dan run test U01-U14, CLI, trust store otomatis:

```powershell
python test/scenarios/run_app.py
```

Manually pakai executable (build ulang)
```powershell
go build -o dist/kelompok17.exe ./cmd/kelompok17
python test/scenarios/run_app.py --cli dist/kelompok17.exe
```

Buat nentuin nama folder, pakai nama folder yang belum ada:

```powershell
python test/scenarios/run_app.py --cli dist/kelompok17.exe --out test/results/app-baru
```

Test langsung dari go
```powershell
go test -v ./...
```

Contoh buat test U14 doang
```powershell
go test -v ./internal/core -run '^TestU14$'
```

Contoh interoperability doang
```powershell
$env:PATH = 'C:\Program Files\Git\usr\bin;' + $env:PATH
go test -v ./test/interop
```
