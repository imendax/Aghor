rule signature_145
{
	meta:
		authro = "0xlsd"
		sample = "03132a0e381567e435ed36e92fd2a54815097b6ba1ccb8de35d160aef22960d5"
	
	
	strings:
		$string_1 = {
			6B 8B ?? ?? ?? ?? 6A
			D9 6B ??
			A8 D6
			36 8B 6A ??
			6B 8B ?? ?? ?? ?? 6A
			D9 6B ??
			A1 ?? ?? ?? ??
			D9 6B ??
			91
			FD
			56
			8B 6A ??
		}
	
	condition:
		any of them
	
}
