rule signature_133
{
	meta:
		authro = "0xlsd"
		sample = "f20c598bf2f9438ed9c2e5096c7cedab951d0c1ed9b87b48cef5d7b08bc48a87"
	
		strings:
		$string_1 = {
			17
			13 A4 BD ?? ?? ?? ??
			17
			13 A4 BD ?? ?? ?? ??
			17
			13 A4 BD ?? ?? ?? ??
			17
			13 A4 BD ?? ?? ?? ??
			17
			13 A4 BD ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
