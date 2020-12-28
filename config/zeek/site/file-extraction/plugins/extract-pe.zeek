@load ../__load__.zeek

module FileExtraction;

hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=5
	{
	if ( meta$mime_type == "application/x-dosexec" )
		break;
	}
