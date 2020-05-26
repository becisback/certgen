# Analisi della scadenza dei certificati v.20200302

<#20200302 F.Beconcini
Utility per l'analisi della scadenza dei certificati #>

$OutputFile= "C:\Users\T000386\Documents\bin\certificati\CertScan.CSV"


$PathList=(`
    "\\nastf2\certificati\ATTIVI", `
    "\\nassi1.local\certificati\ATTIVI", `
    #"\\nassi1.local\certificati\CA_Pubblica\Actalis", `
    "\\nassi1.local\certificati\CA_Pubblica\Global Trust", `
    "\\nassi1.local\certificati\CertificatiInterni" `
    )

$PathList=(`
    "C:\Users\T000386\Documents\TEMP\Certificati" `
    )



#----------------------------------------------------------------------------
#Inizializza l'hash table per i dati del certificato
$Certificato= @{
    File= 'FileFullName'
    Directory= 'FilePath'
    CN= 'CommonName'
    CA= 'CertAuth'
    Expiration= 'Expiration'
    Signature= 'Signature'
    SAN= 'SAN'
    }

#----------------------------------------------------------------------------
#Scrive l'intestazione del file CSV e inizializza il file di output
$Record= "$($Certificato.CA), $($Certificato.CN), $($Certificato.SAN), $($Certificato.Expiration), $($Certificato.Directory)"
Set-Content -Path $OutputFile -Value $Record -force

#----------------------------------------------------------------------------
#Scansiona la struttura delle directory che contengono i certificati
foreach ($Path in $Pathlist) {
    $CertCount++
    Write-Host $Path
    $CertCount= 0

    foreach ($Directory in Get-ChildItem -path $Path) {
        $CertCount++
        #----------------------------------------------------------------------------
        #azzera l'hash table per i dati del certificato
        $Certificato= @{
            File= '***'
            Directory= '***'
            CA='***'
            CN='***'
            Expiration='***'
            Signature= '***'
            SAN= '***'
            Serial= '***'
			}
        
        #----------------------------------------------------------------------------
        #legge la posizione del certificato nel file system
        $Certificato.File= (Get-ChildItem -path $Directory.FullName -filter *.crt).FullName
        $Certificato.Directory= $Directory.FullName

        #----------------------------------------------------------------------------
        #legge il dati del certificato
        $FullCertificato= certutil $Certificato.File
        $NLinea= 0
        foreach ($Linea in $FullCertificato) {
            $NLinea++
			
			if ($Linea -match 'Numero di serie: (.*)') {$Certificato.Serial=  $Matches.1}
			
			if ($Linea -match 'Autorit.* emittente:') {
                $Certificato.CA= $FullCertificato[$NLinea].Substring(7, $FullCertificato[$NLinea].Length -7)
                }

            if ($Linea -match ' NotAfter: (\d\d/\d\d/)(\d\d)') {$Certificato.Expiration= $Matches.1+ '20'+ $Matches.2}
                
            if ($Linea -eq 'Soggetto:') {
                $Certificato.CN= $FullCertificato[$NLinea].Substring(7, $FullCertificato[$NLinea].Length -7)
                }

            if ($Linea -eq '    Nome alternativo soggetto') {
                $Run= 0
                do {
                    if ($FullCertificato[$NLinea + $Run] -match '        Nome DNS=(.*)$') {
                        $Certificato.SAN= $Matches.1 + '; ' + $Certificato.SAN
                        }
                
                    } while ($FullCertificato[$NLinea + ++$Run])
                $Certificato.SAN= $Certificato.SAN.Substring(0, $Certificato.SAN.Length -5)
                if ($Certificato.SAN -eq $Certificato.CN) {$Certificato.SAN= '***'}
                if ($Certificato.SAN -eq "www.$($Certificato.CN); $($Certificato.CN)") {$Certificato.SAN= '***'}
                }
            }
        #----------------------------------------------------------------------------
        #aggiunge un record nel file di output
        $Record= "$($Certificato.Serial), $($Certificato.CA), $($Certificato.CN), $($Certificato.SAN), $($Certificato.Expiration), $($Certificato.Directory)"
        Add-Content $OutputFile $Record
        Write-Host "$CertCount";
        }
    
    }