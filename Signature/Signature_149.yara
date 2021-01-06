rule signature_149
{
	meta:
		author = "0xlsd"
		sample = "547fee099aebd153dc04c25d3e9e138b8760791153e9067dc7e4ff52b79197ba"
	
	
	strings:
		$string_1 = {
			D1 3B
			1E
			C9
			7B ??
			3D 54 D1 3B 0C
			2C 42
			3B 0E
			54
			D1 3B
			05 54 D0 3B 56
			54
			D1 3B
			1E
			C9
			7A ??
			0E
			54
			D1 3B
			1E
			C9
			4C
			3B 04 54
		}
	
	condition:
		any of them
	
}
