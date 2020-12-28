@load ../__load__.zeek

module FileExtraction;

const linux_bin_types: set[string] = {
								"text/x-shellscript",
					   			"application/x-executable"
								};

hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=5
	{
	if ( meta$mime_type in linux_bin_types )
		break;
	}