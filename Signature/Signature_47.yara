rule signature_47
{
	meta:
		author = "0xlsd"
		sample = "c5a96226e1471117e50c880daefa7f79e7d90470bafcd2048ca1bbc81ca863c1"
	
	
	strings:
		$string_1 = {
			F5
			8A D3
			95
			FF 8A ?? ?? ?? ??
			59
			95
			E6 8A
			3C 8A
			F5
			8A 3B
			8A F4
			8A 08
			8A F5
			8A D3
			95
			FE 8A ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
