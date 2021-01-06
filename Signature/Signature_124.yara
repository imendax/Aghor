rule signature_124
{
	meta:
		author = "0xlsd"
		sample = "62ae4ede8dc2d473b12a8a33711b87bb52cce36ea62898d7fd38364d85b9e552"
	

	strings:
		$string_1 = {
			B6 C1
			3D F9 35 C1 E2
			AB
			B6 C1
			04 6D
			DB C1
			2C AB
			B6 C1
			04 6D
			CD C1
			3A AB ?? ?? ?? ??
			B7 C1
			18 AA ?? ?? ?? ??
			32 C1
		}
	
	condition:
		any of them
	
}
