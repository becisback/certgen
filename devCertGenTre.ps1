# Utility per la creazione di certificati V.3
# F.Beconcini 20200610

$Versione='20200610'

$Account= get-item "ENV:\USERNAME"
switch ($Account.Value) {
	"T000386X" {$UserName= "Beconcini"}
	"S540061X" {$UserName= "Mannoni"}
	"S345997X" {$UserName= "Paradisi"}
	default {$UserName= $Account.Value}
}

. (".\Library.ps1")

$FileCSVData= $args[0]
$SingleStep= $args[1]
<#
if (($SingleStep -ne 'CSR') -and ($SingleStep -ne 'CER') -and ($SingleStep -ne 'PFX')) {
	Throw "Opzione Single Step $SingleStep non valida"
}
#>

$Segreto= ''

#------------------------------------------------------------------------------
# Se non esiste il file CSV si esce con un messaggio d'errore
if (!(Test-Path $FileCSVData)) {Throw "Il file dei dati $FileCSVData non esiste"}

$CSV= Import-csv $FileCSVData
#if (($SingleStep) -and ($CSV.Count -gt 1)) {Throw "Non si può eseguire in Single Step se il file CSV contiene più di un record"}

$CertCount= 0
#------------------------------------------------------------------------------
# Lettura delle variabili dal file CSV
foreach ($Certificate in $CSV) {
    $TimeStamp= Get-Date

	#------------------------------------------------------------------------------
	# Si azzera la SubCA perchè viene riutilizzato il valore non inizializzandolo
	# per evitare la rilettura del certificato nell'elaborazione del PFX
	$SubCA= ''

    $CertCount++
    #$PerC= 100/$CSV.Count*($CertCount-1)
    #Write-Progress -Activity "Scan dei certificati" -Status "$CertCount/$($DirList.Count) certificati acquisiti" -PercentComplete $PerC

    if (!$Certificate.CN) {Throw "Errore nel file dei dati $FileCSVData non esiste il CommonName"}

	$Certificate.CN= $Certificate.CN.Trim()

    if ($Certificate.SAN)
        {$MultiSAN= @($Certificate.SAN.split(';').trim())}
    else
        {$MultiSAN= @('---')} #Cast $Multisan ad un array

    if (!$Certificate.SHA) {$Certificate.SHA='SHA256'}

    #------------------------------------------------------------------------------
    #Diverse disposizioni a seconda dell'Ambito di sicurezza in questione
    switch ($Certificate.Ambito) {
        "Public-Produzione" {
            $NAS= "\\nassi1.local\certificati\ATTIVI\"
        }
        "Public-NPE" {
            $NAS= "\\nastf2.testfactory.copergmps\certificati\attivi\"
        }
        "Local" {
            $NAS= "\\nassi1.local\certificati\ATTIVI\"
            $Template= 'CertificateTemplate:WebServerConsorzioGMPS'
            switch ($Certificate.SHA) {
                "SHA1" {
                    $CertAuth= "SE001000456751.testfactory.copergmps\SUBMPS1-TF"
				}
                "SHA256" {
					$CertAuth= "se000000010760.sum.local\SUB01-LOCAL G2"
				}
                default {Throw "`tAlgortmo SHA $($Certificate.SHA) non valido`r`n"}
			}
		}
        "Global" {
            $NAS= "\\nassi1.local\certificati\ATTIVI\"
            $CertAuth= "se000005850760.gmps.global\SUB01-GMPS"
            $Template= 'CertificateTemplate:WebServerGMPS256'
			if ($Certificate.SHA -ne "SHA256") {Throw "`tAlgortmo SHA $($Certificate.SHA) non valido per $($Certificate.Ambiente)`r`n"}
		}
        "NPE" {
            $NAS= "\\nastf2.testfactory.copergmps\certificati\attivi\"
            $CertAuth= "SE001000456751.testfactory.copergmps\SUBMPS1-TF"
            $Template= 'CertificateTemplate:UnixComp2048'
			#if ($Certificate.SHA -ne "SHA256") {Throw "`tAlgortmo SHA $($Certificate.SHA) non valido per $($Certificate.Ambiente)`r`n"}
        }
        default {Throw "`tAmbito $($Certificate.Ambito) non valido`r`n"}
	}

	$CertificateFolder= $NAS + $Certificate.CN + '\'

    Write-Host "`n--------------------------------------------------------------------------------"
    Write-Host "$TimeStamp Elaborazione del certificato #$CertCount $($Certificate.CN)"

	#------------------------------------------------------------------------------
	# Si identifica l'ambiente operativo corrente
	$Ambiente= get-item "ENV:\Ambiente"
	switch ($Ambiente.Value) {
		'SYSPROD' {$AmbienteExe= 'PRODUZIONE'}
		'CODING' {$AmbienteExe= 'NPE'}
		'TFSTRUCT' {$AmbienteExe= 'NPE'}
		default {Throw "Non è stato possibile identificare l'ambiente operativo Produzione/NPE"}
	}

	#------------------------------------------------------------------------------
	# Verifica che la macchina di esecuzione sia consistente con l'ambiente operativo corrente
	# L'errore non è bloccante e si procede con il certificato successivo
	if (($AmbienteExe -eq 'NPE') -and ($NAS -eq "\\nassi1.local\certificati\ATTIVI\")) {
		Write-Host -Foreground black -BackgroundColor Red "`tNon sarà processato il certificato $($Certificate.CN) partendo dall'ambiente di Produzione"
		continue
	}
	elseif (($AmbienteExe -eq 'PRODUZIONE') -and ($NAS -eq "\\nastf2.testfactory.copergmps\certificati\ATTIVI\")) {
		Write-Host -Foreground black -BackgroundColor Red "`tNon sarà processato il certificato $($Certificate.CN) partendo dall'ambiente NPE"
		continue
	}

	#------------------------------------------------------------------------------
	# Se non esiste si determina una nuova cartella di destinazione partendo dalla $Release=1
	$Release= 1
	if(Test-Path $CertificateFolder) {
		#------------------------------------------------------------------------------
		# Se esiste già la cartella Rn si ricava il nome della successiva
		# mettendo il suffisso di release = n+1
		while (Test-Path $($CertificateFolder + "R$Release\")) {$Release++}
	}

	if (!$SingleStep -or ($SingleStep -eq 'OPT')) {
		$FolderDestination= $CertificateFolder + "R$Release\"
	}
	else {
		#------------------------------------------------------------------------------
        # Se siamo in SingleStep, ma non OPT, si lavora nella stessa directory del file CSV
		$FolderDestination= "$(Split-Path $FileCSVData)\"
		$Release--
	}

	#------------------------------------------------------------------------------
	# Si preparano le variabili per i nomi dei file
    $FileOPT= $FolderDestination + $Certificate.CN + ".OPT"	#File delle opzioni per produrre il CSR
    $FileCSR= $FolderDestination + $Certificate.CN + ".CSR"	#File Certificate Sign Request X509 PEM
    $FileCER= $FolderDestination + $Certificate.CN + ".CER"	#Certificato prodotto dalla CA
    $FileRSP= $FolderDestination + $Certificate.CN + ".rsp"	#File con le risposte della CA
    $FilePFX= $FolderDestination + $Certificate.CN + ".PFX"	#File PKCS#12 con chiave pubblica e privata
    #$FTmpPUB= $FolderDestination + $Certificate.CN + "_PUB_tmp.crt"	#File temporaneo con la chiave PUBBLICA
    $FTmpPRV= $FolderDestination + $Certificate.CN + "_PRV_tmp.key"	#File temporaneo con la chiave PRIVATA
    $FilePUB= $FolderDestination + $Certificate.CN + "_PUB.CRT"	#File con la chiave PUBBLICA e KeyChain X509 PEM
    $FilePRV= $FolderDestination + $Certificate.CN + "_PRV.KEY"	#File con la chiave PRIVATA e KeyChain X509 PEM
	$FileDTL= $FolderDestination + $Certificate.CN + ".TXT"	#File di testo con i dettagli del certificato
    $FileCSV= $FolderDestination + $Certificate.CN + ".CSV"	#File CSV necessario per produrre il certificato
	$FileJKS= $FolderDestination + $Certificate.CN + ".JKS"	#File Java Key Store
	$FileRSA= $FolderDestination + $Certificate.CN + "_RSA.KEY"	#File della chiave privata in formato RSA
	$FileRCD= $FolderDestination + $Certificate.CN + ".RCD"	#File Record per aggiornare l'inventario


	#------------------------------------------------------------------------------
	# Si compone il contenuto informativo per il file TXT
	$Details=  `
		"# CertGenTre v.$Versione   $TimeStamp   $SingleStep`r`n`r`n" + `
		"Codice APM`r`n`t$($Certificate.CodiceAPM)`r`n`r`n" + `
		"Common Name`r`n`t$($Certificate.CN)`r`n`r`n" + `
		"Subject Alternative Names`r`n`t$MultiSAN`r`n`r`n" + `
		"Algoritmo SHA`r`n`t$($Certificate.SHA)`r`n`r`n" + `
		"Certificate Folder`r`n`t$FolderDestination`r`n`r`n" + `
		"Certificato elaborato da`r`n`t$UserName`r`n`r`n"

	#------------------------------------------------------------------------------
	# Creazione del file DTL con i primi dettagli del certificato
	#Set-Content -Path $FileDTL -Value $Details -force  1>$null

	if ((!$SingleStep) -or ($SingleStep -eq 'OPT')) {
		#------------------------------------------------------------------------------
		# Crea la directory di destinazione
		New-Item -Path $FolderDestination -ItemType directory   1>$null

		#------------------------------------------------------------------------------
        # Creazione del file CSV
	    $Certificate|Export-Csv $FileCSV  1>$null

		#------------------------------------------------------------------------------
		#Si compone la sezione [Extentions] per il file delle opzioni
		$Extentions= `
			"[Extensions]" + `
			"`n2.5.29.17=`"{text}`"" + `
			"`n_continue_=`"EMail=hostmaster@mps.it&`"" + `
			"`n_continue_=`"DNS=$($Certificate.CN)"

		#------------------------------------------------------------------------------
		# si aggiungono eventuali SAN. $MultiSAN potrà essere una stringa o un array
		if ($MultiSAN -ne '---') {for ($i=0; $i -lt $MultiSAN.Count; $i++) {$Extentions=$Extentions + "&`"`n_continue_=`"DNS=" + $MultiSAN[$i]}}

		#------------------------------------------------------------------------------
		#Si chiude la stringa delle estensioni con opportune "
		$Extentions= $Extentions + '"'
		$Subject= "cn=$($Certificate.CN),ou=Consorzio Operativo Gruppo MPS,o=Banca Monte dei Paschi di Siena S.p.A,c=IT,l=Siena,s=Siena"

		#------------------------------------------------------------------------------
		#Predisposizione del contenuto del file delle opzioni
		$OPT= `
			"[NewRequest]`n" + `
			"Subject=`"$Subject,PostalCode=53100`"" + `
			"`nExportable=TRUE" + `
			"`nKeyLength=2048" + `
			"`nKeySpec=1" + `
			"`nRequestType=`"PKCS10`"" + `
			"`nKeyUsage=0xA0" + `
			"`nFriendlyName=`"$($Certificate.CN)`"" + `
			"`nHashAlgorithm=$($Certificate.SHA)" + `
			"`nSMIME=False" + `
			"`nUseExistingKeySet=False" + `
			"`n[EnhancedKeyUsageExtension]" + `
			"`nOID=1.3.6.1.5.5.7.3.1" + `
			"`nOID=1.3.6.1.5.5.7.3.2`n" + `
			$Extentions


        #------------------------------------------------------------------------------
        # Creazione del file OPT delle opzioni per il certificato
        Set-Content -Path $FileOPT -Value $OPT -force  1>$null
	}

	if ((!$SingleStep) -or ($SingleStep -eq 'CSR')) {
		#------------------------------------------------------------------------------
        # Creazione del file CSR Certificate Sign Request
		if (!(Test-Path $FileOPT)) {
			Write-Host -Foreground black -background Red "`tNon esiste il file delle opzioni $FileOPT"
			continue
		}
        & certreq -new $FileOPT $FileCSR  1>$null
		#------------------------------------------------------------------------------
        # Se si richiede un certificato Public ci si passa al record successivo del CSV
		if (($Certificate.Ambito -eq 'Public-Produzione') -or ($Certificate.Ambito -eq 'Public-NPE')) {
			Write-Host -Foreground black -background Green "`tDati del certificato salvati in $FolderDestination"
			continue
		}
		
	}

	if ((!$SingleStep) -or ($SingleStep -eq 'CER')) {
		#------------------------------------------------------------------------------
        # Firma del certificato
        if (!(Test-Path $FileCSR)) {
			Write-Host -Foreground black -background Red "`tNon esiste il Certificate Sign Request $FileCSR"
			continue
		}
        & certreq -submit -config $CertAuth -attrib $Template $FileCSR $FileCER  1>$null
    }

	if ((!$SingleStep) -or ($SingleStep -eq 'CRT')) {
        if (!(Test-Path $FileCER)) {
			Write-Host -Foreground black -background Red "`tNon esiste il Certificato firmato $FileCER"
			continue
		}

		#------------------------------------------------------------------------------
		# Si esaminano i dati nel certificato prodotto
		$FullCertificate= $(& $OpenSSL x509 -in $FileCER -text -noout)  2>$null
		$NLinea= 0

		do {
			if ($FullCertificate[$NLinea] -match 'Issuer: C=.+, CN=(.+)') {$SubCA= $Matches.1}
		} while (($NLinea++ -gt $FullCertificate.Count) -or !$SubCA)

		$Activation= ''
		do {
			if ($FullCertificate[$NLinea] -match 'Not Before: (.{3})\s+(\d+)\s+.+:.+:.+\s(\d{4}) GMT') {
				switch ($Matches.1) {
					'Jan' {$Activation= $Matches.2 + ' Gen ' + $Matches.3}
					'Feb' {$Activation= $Matches.2 + ' Feb ' + $Matches.3}
					'Mar' {$Activation= $Matches.2 + ' Mar ' + $Matches.3}
					'Apr' {$Activation= $Matches.2 + ' Apr ' + $Matches.3}
					'May' {$Activation= $Matches.2 + ' Mag ' + $Matches.3}
					'Jun' {$Activation= $Matches.2 + ' Giu ' + $Matches.3}
					'Jul' {$Activation= $Matches.2 + ' Lug ' + $Matches.3}
					'Aug' {$Activation= $Matches.2 + ' Ago ' + $Matches.3}
					'Sep' {$Activation= $Matches.2 + ' Set ' + $Matches.3}
					'Oct' {$Activation= $Matches.2 + ' Ott ' + $Matches.3}
					'Nov' {$Activation= $Matches.2 + ' Nov ' + $Matches.3}
					'Dec' {$Activation= $Matches.2 + ' Dic ' + $Matches.3}
				}
			}
		} while (($NLinea++ -gt $FullCertificate.Count) -or !$Activation)

		$Expiration= ''
		do {
			if ($FullCertificate[$NLinea] -match 'Not After : (.{3})\s+(\d+)\s+.+:.+:.+\s(\d{4}) GMT') {
				switch ($Matches.1) {
					'Jan' {$Expiration= $Matches.2 + ' Gen ' + $Matches.3}
					'Feb' {$Expiration= $Matches.2 + ' Feb ' + $Matches.3}
					'Mar' {$Expiration= $Matches.2 + ' Mar ' + $Matches.3}
					'Apr' {$Expiration= $Matches.2 + ' Apr ' + $Matches.3}
					'May' {$Expiration= $Matches.2 + ' Mag ' + $Matches.3}
					'Jun' {$Expiration= $Matches.2 + ' Giu ' + $Matches.3}
					'Jul' {$Expiration= $Matches.2 + ' Lug ' + $Matches.3}
					'Aug' {$Expiration= $Matches.2 + ' Ago ' + $Matches.3}
					'Sep' {$Expiration= $Matches.2 + ' Set ' + $Matches.3}
					'Oct' {$Expiration= $Matches.2 + ' Ott ' + $Matches.3}
					'Nov' {$Expiration= $Matches.2 + ' Nov ' + $Matches.3}
					'Dec' {$Expiration= $Matches.2 + ' Dic ' + $Matches.3}
				}
			}
		} while (($NLinea++ -gt $FullCertificate.Count) -or !$Expiration)

		switch ($SubCA) {
			"AXA-Issuing-CA-PR1" {										#CA Interna AXA
				$IntermediateCA=''
				$RootCA= 'AXA-Enterprise-Root-CA'}

			"Sectigo RSA Extended Validation Secure Server CA" {		#CA Sectigo per i certificati Extended Validation
				$IntermediateCA='USERTrust RSA Certification Authority'
				$RootCA= 'AAA Certificate Services'}
				
			"Sectigo RSA Organization Validation Secure Server CA" {  	#CA Sectigo per i certificati MultiSAN
				$IntermediateCA='USERTrust RSA Certification Authority'
				$RootCA= 'AAA Certificate Services'}

			"USERTrust RSA Organization Validation Secure Server CA" {	#CA Sectigo per i certificati RealWEB
				$IntermediateCA='USERTrust RSA Certification Authority'
				$RootCA= 'AAA Certificate Services'}

			"SUB01-GMPS" {												#CA MPS Global per la intranet
				$IntermediateCA=''
				$RootCA= 'RootCA-GMPS'}

			"SUBMPS1-TF" {												#CA MPS TestFactory
				$IntermediateCA=''
				$RootCA= 'ROOTMPS-TF'}

			"SUB01-LOCAL G2" {											#CA MPS Local per la intranet
				$IntermediateCA=''
				$RootCA= 'RootCA-GMPS'}

			default {Throw "`tSubCA non censita nel programma: $SubCA`r`n"}
		}

		$FileSubCA= $NAS + $SubCA + '\' + $SubCA + '.CRT'
		if (!(Test-Path $FileSubCA)) {Throw "Certificato della SubCA $SubCA non trovato: $FileSubCA"}
		
		if ($IntermediateCA -ne '') {
			$FileIntermediateCA= $NAS + $IntermediateCA + '\' + $IntermediateCA + '.CRT'
			if (!(Test-Path $FileSubCA)) {Throw "Certificato della IntermediateCA di $SubCA non trovato: $FileIntermediateCA"}
		}

		$FileRootCA= $NAS + $RootCA + '\' + $RootCA + '.CRT'
		if (!(Test-Path $FileRootCA)) {Throw "Certificato della RootCA di $SubCA non trovato: $FileRootCA"}

		#------------------------------------------------------------------------------
		# Si compone la parte PUBBLICA del certificato con la catena di certificazione
		if (!(Test-Path $FileCER)) {Throw "Non esiste il file del certificato $FileCER"}
		$CertPUB= Get-Content -Path $FileCER
		$CertPUB= $CertPUB + "`r`n`r`n" + $(Get-Content -Path $FileSubCA)
		if ($IntermediateCA -ne '') {$CertPUB= $CertPUB + "`r`n`r`n" + $(Get-Content -Path $FileIntermediateCA)}
		$CertPUB= $CertPUB + "`r`n`r`n" + $(Get-Content -Path $FileRootCA)
		$CertPUB | Set-Content -Path $FilePUB -force  1>$null

		if ($SingleStep -eq 'CRT') {
			#------------------------------------------------------------------------------
			# Solo per certificati prodotti a partire dal CSR si aggiungono i CER della 
			# catena di certificazione insieme agli altri file
			Copy-Item -path $FileSubCA -Destination $FolderDestination
			if ($IntermediateCA -ne '') {Copy-Item -path $FileIntermediateCA -Destination $FolderDestination}
			Copy-Item -path $FileRootCA -Destination $FolderDestination
		}
    }

	if ((!$SingleStep) -or ($SingleStep -eq 'PFX')) {
		if (!(Test-Path $FileCER)) {
			Write-Host -Foreground black -background Red "`tNon esiste il file delcertificato $FileCER"
			continue
		}

		#------------------------------------------------------------------------------
		# Acquisizione del certificato nello storage personale e ricombinazione con la 
		# chiave privata
		& certreq -accept $FileCER  1>$null

		if (!$Certificate.PassWD) {
			if (($Certificate.Ambito -eq 'Public-Produzione') -or ($Certificate.Ambito -eq 'Public-NPE'))
				{$Certificate.PassWD=[System.Web.Security.Membership]::GeneratePassword(10,0)}
			else
				{$Certificate.PassWD='12345678'}
		}

		#------------------------------------------------------------------------------
		# Si prepara una riga per il file TXT con la password
		$Segreto= "Password`r`n`t$($Certificate.PassWD)"
		
		#------------------------------------------------------------------------------
		# Export del certificato in formato PFX con password
		& certutil -user -p $Certificate.PassWD -exportPFX my $Certificate.CN $FilePFX  1>$null

		#------------------------------------------------------------------------------
		# Si cancella il certificato dallo storage "my" dopo che è stato esportato
		& certutil -delstore -user my $Certificate.CN  1>$null

		#------------------------------------------------------------------------------
		# Estrazione della chiave privata del certificato in formato RSA dal PFX
		& $OpenSSL rsa -in $FilePFX -inform PKCS12 -passin pass:$($Certificate.PassWD) -out $FileRSA *>$null

		#------------------------------------------------------------------------------
		# Estrazione della chiave privata del certificato in formato X509 PEM dal PFX
		#==============================================================================
		# Toglierre l'opzione NODES che estrae la chiave privata in chiaro
		& $OpenSSL pkcs12 -in $FilePFX -out $FTmpPRV -clcerts -nodes -password pass:$($Certificate.PassWD)  *>$null

		#------------------------------------------------------------------------------
		# Si esaminano i dati nel certificato prodotto se la $SubCA non è già stata inizializzata
		# nell'elaborazione del CER
		if (!$SubCA) {
			$FullCertificate= $(& $OpenSSL x509 -in $FileCER -text -noout)  2>$null
			$NLinea= 0

			do {
				if ($FullCertificate[$NLinea] -match 'Issuer: C=.+, CN=(.+)') {$SubCA= $Matches.1}
			} while (($NLinea++ -gt $FullCertificate.Count) -or !$SubCA)

			$Activation= ''
			do {
				if ($FullCertificate[$NLinea] -match 'Not Before: (.{3})\s+(\d+)\s+.+:.+:.+\s(\d{4}) GMT') {
					switch ($Matches.1) {
						'Jan' {$Activation= $Matches.2 + ' Gen ' + $Matches.3}
						'Feb' {$Activation= $Matches.2 + ' Feb ' + $Matches.3}
						'Mar' {$Activation= $Matches.2 + ' Mar ' + $Matches.3}
						'Apr' {$Activation= $Matches.2 + ' Apr ' + $Matches.3}
						'May' {$Activation= $Matches.2 + ' Mag ' + $Matches.3}
						'Jun' {$Activation= $Matches.2 + ' Giu ' + $Matches.3}
						'Jul' {$Activation= $Matches.2 + ' Lug ' + $Matches.3}
						'Aug' {$Activation= $Matches.2 + ' Ago ' + $Matches.3}
						'Sep' {$Activation= $Matches.2 + ' Set ' + $Matches.3}
						'Oct' {$Activation= $Matches.2 + ' Ott ' + $Matches.3}
						'Nov' {$Activation= $Matches.2 + ' Nov ' + $Matches.3}
						'Dec' {$Activation= $Matches.2 + ' Dic ' + $Matches.3}
					}
				}
			} while (($NLinea++ -gt $FullCertificate.Count) -or !$Activation)

			$Expiration= ''
			do {
				if ($FullCertificate[$NLinea] -match 'Not After : (.{3})\s+(\d+)\s+.+:.+:.+\s(\d{4}) GMT') {
					switch ($Matches.1) {
						'Jan' {$Expiration= $Matches.2 + ' Gen ' + $Matches.3}
						'Feb' {$Expiration= $Matches.2 + ' Feb ' + $Matches.3}
						'Mar' {$Expiration= $Matches.2 + ' Mar ' + $Matches.3}
						'Apr' {$Expiration= $Matches.2 + ' Apr ' + $Matches.3}
						'May' {$Expiration= $Matches.2 + ' Mag ' + $Matches.3}
						'Jun' {$Expiration= $Matches.2 + ' Giu ' + $Matches.3}
						'Jul' {$Expiration= $Matches.2 + ' Lug ' + $Matches.3}
						'Aug' {$Expiration= $Matches.2 + ' Ago ' + $Matches.3}
						'Sep' {$Expiration= $Matches.2 + ' Set ' + $Matches.3}
						'Oct' {$Expiration= $Matches.2 + ' Ott ' + $Matches.3}
						'Nov' {$Expiration= $Matches.2 + ' Nov ' + $Matches.3}
						'Dec' {$Expiration= $Matches.2 + ' Dic ' + $Matches.3}
					}
				}
			} while (($NLinea++ -gt $FullCertificate.Count) -or !$Expiration)

			switch ($SubCA) {
				"AXA-Issuing-CA-PR1" {										#CA Interna AXA
					$IntermediateCA=''
					$RootCA= 'AXA-Enterprise-Root-CA'}

				"Sectigo RSA Extended Validation Secure Server CA" {		#CA Sectigo per i certificati Extended Validation
					$IntermediateCA=''
					$RootCA= 'USERTrust RSA Certification Authority'}

				"Sectigo RSA Organization Validation Secure Server CA" {  	#CA Sectigo per i certificati MultiSAN
					$IntermediateCA=''
					$RootCA= 'USERTrust RSA Certification Authority'}

				"USERTrust RSA Organization Validation Secure Server CA" {	#CA Sectigo per i certificati RealWEB
					$IntermediateCA=''
					$RootCA= 'USERTrust RSA Certification Authority'}

				"SUB01-GMPS" {												#CA MPS Global per la intranet
					$IntermediateCA=''
					$RootCA= 'RootCA-GMPS'}

				"SUBMPS1-TF" {												#CA MPS TestFactory
					$IntermediateCA=''
					$RootCA= 'ROOTMPS-TF'}

				"SUB01-LOCAL G2" {											#CA MPS Local per la intranet
					$IntermediateCA=''
					$RootCA= 'RootCA-GMPS'}

				default {Throw "`tSubCA non censita nel programma: $SubCA`r`n"}
			}

			$FileSubCA= $NAS + $SubCA + '\' + $SubCA + '.CRT'
			if (!(Test-Path $FileSubCA)) {Throw "Certificato della SubCA $SubCA non trovato: $FileSubCA"}
			
			if ($IntermediateCA -ne '') {
				$FileIntermediateCA= $NAS + $IntermediateCA + '\' + $IntermediateCA + '.CRT'
				if (!(Test-Path $FileSubCA)) {Throw "Certificato della IntermediateCA di $SubCA non trovato: $FileIntermediateCA"}
			}

			$FileRootCA= $NAS + $RootCA + '\' + $RootCA + '.CRT'
			if (!(Test-Path $FileRootCA)) {Throw "Certificato della RootCA di $SubCA non trovato: $FileRootCA"}
		}

		#------------------------------------------------------------------------------
		# Si compone la parte PRIVATA del certificato con la catena di certificazione
		if (!(Test-Path $FTmpPRV)) {Throw "Non è stato prodotto il file con la chiave privata $FTmpPRV"}
		$CertPRV= Get-Content -Path $FTmpPRV
		$CertPRV= $CertPRV + "`r`n`r`n" + $(Get-Content -Path $FileSubCA)
		if ($IntermediateCA -ne '') {$CertPRV= $CertPRV + "`r`n`r`n" + $(Get-Content -Path $FileIntermediateCA)}
		$CertPRV= $CertPRV + "`r`n`r`n" + $(Get-Content -Path $FileRootCA)
		$CertPRV | Set-Content -Path $FilePRV -force  1>$null

		#------------------------------------------------------------------------------
		# Si crea il Java Key Store con il certificato Alias= $DNSName
		if ($(keytool -list -storetype pkcs12 -keystore $FilePFX -deststorepass $Certificate.PassWD)[6] -match "(.*?),.*") {
			$CertificateAlias= $Matches[1]
		}
		else {Throw "Non trovato il certificato nel PFX"}

		keytool -importkeystore `
			-srcstoretype pkcs12 -srckeystore $FilePFX -srcstorepass $Certificate.PassWD -srcalias $CertificateAlias `
			-deststoretype jks -destkeystore $FileJKS -deststorepass $Certificate.PassWD -destalias $Certificate.CN `
			-noprompt *>null 
		keytool -import -alias $SubCA -file $FileSubCA -keystore $FileJKS -deststorepass $Certificate.PassWD -noprompt *>null 
		if ($IntermediateCA -ne '') {
			keytool -import -alias $IntermediateCA -file $FileIntermediateCA -trustcacerts -keystore $FileJKS -deststorepass $Certificate.PassWD -noprompt *>null}
		keytool -import -alias $RootCA -file $FileRootCA -trustcacerts -keystore $FileJKS -deststorepass $Certificate.PassWD -noprompt *>null 
	}

	#------------------------------------------------------------------------------
	# Si Cancellano i file non necessari
    if (Test-Path $FileRSP) {Remove-Item -Path $FileRSP}
    #if (Test-Path $FTmpPUB) {Remove-Item -Path $FTmpPUB}
    if (Test-Path $FTmpPRV) {Remove-Item -Path $FTmpPRV}

    #------------------------------------------------------------------------------
    # Se il certificato è al primo rilascio ne viene fatta una copia anche nella directory padre di R1
    if ($Release -eq 1) {
        if (Test-Path $FilePUB) {Copy-Item -Path $FilePUB -Destination "$CertificateFolder"}
    }

	#------------------------------------------------------------------------------
	# Si compone il contenuto informativo per il file TXT
	if ($SubCA) {
		$Details= $Details + `
			"Certification SUB Authority`r`n`t" + $SubCA + "`r`n`r`n" + `
			"Certification Root Authority`r`n`t" + $RootCA + "`r`n`r`n" + `
			"NotBefore`r`n`t" + $Activation + "`r`n`r`n" + `
			"NotAfter`r`n`t" + $Expiration + "`r`n`r`n" + `
			$Segreto
	}
	
	#------------------------------------------------------------------------------
	# Aggiunge al file DTL i dettagli del certificato
	Set-Content -Path $FileDTL -Value $Details -force  1>$null

	$Record= `
		$Certificate.CodiceAPM + "`t" + `
		$Certificate.CN + "`t" + `
		$Certificate.SAN + "`t" + `
		$Expiration + "`t" + `
		$CertificateFolder + "`t" + `
		$SubCA + "`t" + `
		$UserName
	#------------------------------------------------------------------------------
	# Crea il file Record per aggiornare l'inventario dei certificati
	Set-Content -Path $FileRCD -Value $Record -force  1>$null


	
    Write-Host -Foreground black -background Green "`tDati del certificato salvati in $FolderDestination"

}
Write-Host

exit
