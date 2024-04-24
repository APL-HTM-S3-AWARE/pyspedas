from .load import load
from pytplot import options
from pyspedas.utilities.datasets import find_datasets


def mfi(trange=['2018-11-5', '2018-11-6'],
        datatype='h3',
        suffix='',  
        get_support_data=False, 
        varformat=None,
        varnames=[],
        downloadonly=False,
        notplot=False,
        no_update=False,
        time_clip=False):
    """
    Loads data from the ACE Fluxgate Magnetometer
    
    Parameters
    ----------

        trange : list of str
            time range of interest [starttime, endtime] with the format 
            'YYYY-MM-DD','YYYY-MM-DD'] or to specify more or less than a day 
            ['YYYY-MM-DD/hh:mm:ss','YYYY-MM-DD/hh:mm:ss']
            Default: ['2018-11-5', '2018-11-6']

        datatype: str
            Data type; Valid options:
                h0: 16-Second Level 2 Data
                h1: 4-Minute Level 2 Data
                h2: 1-Hour Level 2 Data
                h3: (default) 1-Second Level 2 Data
                k0: 5-Minute Key Parameters [PRELIM]
                k1: 16-Second Key Parameters [PRELIM]
                k2: 1-Hour Key Parameters [PRELIM] 
            Default: 'h3'

        suffix: str
            The tplot variable names will be given this suffix.  By default, 
            no suffix is added.
            Default: ''

        get_support_data: bool
            Data with an attribute "VAR_TYPE" with a value of "support_data"
            will be loaded into tplot.  By default, only loads in data with a 
            "VAR_TYPE" attribute of "data".
            Default: False

        varformat: str
            The file variable formats to load into tplot.  Wildcard character
            "*" is accepted.  By default, all variables are loaded in.
            Default: None

        varnames: list of str
            List of variable names to load (if not specified,
            all data variables are loaded)
            Default: []

        downloadonly: bool
            Set this flag to download the CDF files, but not load them into 
            tplot variables
            Default: False

        notplot: bool
            Return the data in hash tables instead of creating tplot variables
            Default: False

        no_update: bool
            If set, only load data from your local cache
            Default: False

        time_clip: bool
            Time clip the variables to exactly the range specified in the trange keyword
            Default: False

    Returns
    ----------

        List of tplot variables created.

    Examples
    ----------

        >>> import pyspdedas
        >>> from pytplot import tplot
        >>> mfi_vars = pyspedas.ace.mfi(trange=['2018-11-5', '2018-11-6'])
        >>> tplot(['BGSEc', 'Magnitude'])

    """
    tvars = load(instrument='fgm', trange=trange, datatype=datatype, suffix=suffix, get_support_data=get_support_data, varformat=varformat, varnames=varnames, downloadonly=downloadonly, notplot=notplot, time_clip=time_clip, no_update=no_update)
    
    if tvars is None or notplot or downloadonly:
        return tvars

    if 'Magnitude'+suffix in tvars:
        options('Magnitude'+suffix, 'ytitle', 'ACE MFI')
        options('Magnitude'+suffix, 'legend_names',  'Magnitude')

    if 'BGSEc'+suffix in tvars:
        options('BGSEc'+suffix, 'ytitle', 'ACE MFI')
        options('BGSEc'+suffix, 'legend_names',  ['Bx', 'By', 'Bz'])

    return tvars


def swe(trange=['2018-11-5', '2018-11-6'],
        datatype='h0',
        suffix='',  
        get_support_data=False, 
        varformat=None,
        varnames=[],
        downloadonly=False,
        notplot=False,
        no_update=False,
        time_clip=False):
    """
    Load data from the ACE Solar Wind Electron, Proton and Alpha Monitor (SWEPAM)
    
    Parameters
    ----------

        trange : list of str

            time range of interest [starttime, endtime] with the format 
            'YYYY-MM-DD','YYYY-MM-DD'] or to specify more or less than a day 
            ['YYYY-MM-DD/hh:mm:ss','YYYY-MM-DD/hh:mm:ss']
            Default: ['2018-11-5', '2018-11-6']

        datatype: str

            Data type; Valid options:

                h0: (default) 64-Second Level 2 Data
                h2: 1-Hour Level 2 Data
                k0: 5-Minute Key Parameters [PRELIM] 
                k1: 1-Hour Key Parameters [PRELIM]

            Default: 'h0'

        suffix: str
            The tplot variable names will be given this suffix.  By default, 
            no suffix is added.
            Default: ''

        get_support_data: bool
            Data with an attribute "VAR_TYPE" with a value of "support_data"
            will be loaded into tplot.  By default, only loads in data with a 
            "VAR_TYPE" attribute of "data".
            Default: False

        varformat: str
            The file variable formats to load into tplot.  Wildcard character
            "*" is accepted.  By default, all variables are loaded in.
            Default: None

        varnames: list of str
            List of variable names to load (if not specified,
            all data variables are loaded)
            Default: []

        downloadonly: bool
            Set this flag to download the CDF files, but not load them into 
            tplot variables
            Default: False

        notplot: bool
            Return the data in hash tables instead of creating tplot variables
            Default: False

        no_update: bool
            If set, only load data from your local cache
            Default: False

        time_clip: bool
            Time clip the variables to exactly the range specified in the trange keyword
            Default: False

    Returns
    ----------

        List of tplot variables created.

    Examples
    ----------

        >>> import pyspdedas
        >>> from pytplot import tplot
        >>> swe_vars = pyspedas.ace.swe(trange=['2018-11-5', '2018-11-6'])
        >>> tplot(['Vp', 'Tpr'])

    """
    return load(instrument='swe', trange=trange, datatype=datatype, suffix=suffix, get_support_data=get_support_data, varformat=varformat, varnames=varnames, downloadonly=downloadonly, notplot=notplot, time_clip=time_clip, no_update=no_update)


def epam(trange=['2018-11-5', '2018-11-6'],
        datatype='k0',
        suffix='',  
        get_support_data=False, 
        varformat=None,
        varnames=[],
        downloadonly=False,
        notplot=False,
        no_update=False,
        time_clip=False):
    """
    Load data from the ACE Electron Proton Alpha Monitor (EPAM)
    
    Parameters
    ----------

        trange : list of str
            time range of interest [starttime, endtime] with the format 
            'YYYY-MM-DD','YYYY-MM-DD'] or to specify more or less than a day 
            ['YYYY-MM-DD/hh:mm:ss','YYYY-MM-DD/hh:mm:ss']
            Default: ['2018-11-5', '2018-11-6']

        datatype: str
            Data type; Valid options:
                h1: 5-Minute Level 2 Data
                h2: 1-Hour Level 2 Data
                h3: 12-second Level 2 Data
                k0: (default) 5-Minute Key Parameters
                k1: 1-Hour Key Parameters
            Default: 'k0'

        suffix: str
            The tplot variable names will be given this suffix.  By default, 
            no suffix is added.
            Default: ''

        get_support_data: bool
            Data with an attribute "VAR_TYPE" with a value of "support_data"
            will be loaded into tplot.  By default, only loads in data with a 
            "VAR_TYPE" attribute of "data".
            Default: False

        varformat: str
            The file variable formats to load into tplot.  Wildcard character
            "*" is accepted.  By default, all variables are loaded in.
            Default: None

        varnames: list of str
            List of variable names to load (if not specified,
            all data variables are loaded)
            Default: []

        downloadonly: bool
            Set this flag to download the CDF files, but not load them into 
            tplot variables
            Default: False

        notplot: bool
            Return the data in hash tables instead of creating tplot variables
            Default: False

        no_update: bool
            If set, only load data from your local cache
            Default: False

        time_clip: bool
            Time clip the variables to exactly the range specified in the trange keyword
            Default: False

    Returns
    ----------

        List of tplot variables created.
    
    Examples
    ----------

        >>> import pyspdedas
        >>> from pytplot import tplot
        >>> epam_vars = pyspedas.ace.epam(trange=['2018-11-5', '2018-11-6'])
        >>> tplot(['H_lo', 'Ion_very_lo', 'Ion_lo', 'Ion_mid', 'Ion_hi', 'Electron_lo', 'Electron_hi'])

    """
    return load(instrument='epm', trange=trange, datatype=datatype, suffix=suffix, get_support_data=get_support_data, varformat=varformat, varnames=varnames, downloadonly=downloadonly, notplot=notplot, time_clip=time_clip, no_update=no_update)


def cris(trange=['2018-11-5', '2018-11-6'],
        datatype='h2',
        suffix='',  
        get_support_data=False, 
        varformat=None,
        varnames=[],
        downloadonly=False,
        notplot=False,
        no_update=False,
        time_clip=False):
    """
    Load data from the ACE Cosmic Ray Isotope Spectrometer (CRIS)
    
    Parameters
    ----------

        trange : list of str
            time range of interest [starttime, endtime] with the format 
            'YYYY-MM-DD','YYYY-MM-DD'] or to specify more or less than a day 
            ['YYYY-MM-DD/hh:mm:ss','YYYY-MM-DD/hh:mm:ss']
            Default:['2018-11-5', '2018-11-6']

        datatype: str
            Data type; Valid options:
                h2: (default) 1-Hour Level 2 Data
                h3: Daily-averaged Level 2 Data
            Default: 'h2'

        suffix: str
            The tplot variable names will be given this suffix.  By default, 
            no suffix is added.
            Default: ''

        get_support_data: bool
            Data with an attribute "VAR_TYPE" with a value of "support_data"
            will be loaded into tplot.  By default, only loads in data with a 
            "VAR_TYPE" attribute of "data".
            Default: False

        varformat: str
            The file variable formats to load into tplot.  Wildcard character
            "*" is accepted.  By default, all variables are loaded in.
            Default: None

        varnames: list of str
            List of variable names to load (if not specified,
            all data variables are loaded)
            Default: []

        downloadonly: bool
            Set this flag to download the CDF files, but not load them into 
            tplot variables
            Default: False

        notplot: bool
            Return the data in hash tables instead of creating tplot variables
            Default: False

        no_update: bool
            If set, only load data from your local cache
            Default: False

        time_clip: bool
            Time clip the variables to exactly the range specified in the trange keyword
            Default: False

    Returns
    ----------

        List of tplot variables created.

    Examples
    ----------

        >>> import pyspdedas
        >>> from pytplot import tplot
        >>> cris_vars = pyspedas.ace.cris(trange=['2018-11-5', '2018-11-6'])
        >>> tplot(['flux_B', 'flux_C', 'flux_N', 'flux_O', 'flux_F', 'flux_Ne'])

    """
    return load(instrument='cris', trange=trange, datatype=datatype, suffix=suffix, get_support_data=get_support_data, varformat=varformat, varnames=varnames, downloadonly=downloadonly, notplot=notplot, time_clip=time_clip, no_update=no_update)


def sis(trange=['2018-11-5', '2018-11-6'],
        datatype='k0',
        suffix='',  
        get_support_data=False, 
        varformat=None,
        varnames=[],
        downloadonly=False,
        notplot=False,
        no_update=False,
        time_clip=False):
    """
    Load data from the ACE Solar Isotope Spectrometer (SIS)
    
    Parameters
    ----------

        trange : list of str
            time range of interest [starttime, endtime] with the format 
            'YYYY-MM-DD','YYYY-MM-DD'] or to specify more or less than a day 
            ['YYYY-MM-DD/hh:mm:ss','YYYY-MM-DD/hh:mm:ss']
            Default: ['2018-11-5', '2018-11-6']

        datatype: str
            Data type; Valid options:
                h1: 256-sec Level 2 Data
                h2: 1-Hour Level 2 Data
                k0: 1-Hour Key Parameters
            Default: 'k0'

        suffix: str
            The tplot variable names will be given this suffix.  By default, 
            no suffix is added.
            Default: ''

        get_support_data: bool
            Data with an attribute "VAR_TYPE" with a value of "support_data"
            will be loaded into tplot.  By default, only loads in data with a 
            "VAR_TYPE" attribute of "data".
            Default: False

        varformat: str
            The file variable formats to load into tplot.  Wildcard character
            "*" is accepted.  By default, all variables are loaded in.
            Default: None

        varnames: list of str
            List of variable names to load (if not specified,
            all data variables are loaded)
            Default: []

        downloadonly: bool
            Set this flag to download the CDF files, but not load them into 
            tplot variables
            Default: False

        notplot: bool
            Return the data in hash tables instead of creating tplot variables
            Default: False

        no_update: bool
            If set, only load data from your local cache
            Default: False

        time_clip: bool
            Time clip the variables to exactly the range specified in the trange keyword
            Default: False

    Returns
    --------

        List of tplot variables created.

    Examples
    ----------

        >>> import pyspdedas
        >>> from pytplot import tplot
        >>> sis_vars = pyspedas.ace.sis(trange=['2018-11-5', '2018-11-6'])
        >>> tplot(['H_lo', 'H_hi', 'CNO_lo', 'CNO_hi', 'Z_ge_10'])

    """
    return load(instrument='sis', trange=trange, datatype=datatype, suffix=suffix, get_support_data=get_support_data, varformat=varformat, varnames=varnames, downloadonly=downloadonly, notplot=notplot, time_clip=time_clip, no_update=no_update)


def uleis(trange=['2018-11-5', '2018-11-6'],
        datatype='h2',
        suffix='',  
        get_support_data=False, 
        varformat=None,
        varnames=[],
        downloadonly=False,
        notplot=False,
        no_update=False,
        time_clip=False):
    """
    Load data from the ACE Ultra Low Energy Isotope Spectrometer (ULEIS)
    
    Parameters
    ----------

        trange : list of str
            time range of interest [starttime, endtime] with the format 
            'YYYY-MM-DD','YYYY-MM-DD'] or to specify more or less than a day 
            ['YYYY-MM-DD/hh:mm:ss','YYYY-MM-DD/hh:mm:ss']
            Default: ['2018-11-5', '2018-11-6']

        datatype: str
            Data type; Valid options:
                h2: 1-Hour Level 2 Data
            Default; 'h2'

        suffix: str
            The tplot variable names will be given this suffix.  By default, 
            no suffix is added.
            Default: ''

        get_support_data: bool
            Data with an attribute "VAR_TYPE" with a value of "support_data"
            will be loaded into tplot.  By default, only loads in data with a 
            "VAR_TYPE" attribute of "data".
            Default: False

        varformat: str
            The file variable formats to load into tplot.  Wildcard character
            "*" is accepted.  By default, all variables are loaded in.
            Default: None

        varnames: list of str
            List of variable names to load (if not specified,
            all data variables are loaded)
            Default: []

        downloadonly: bool
            Set this flag to download the CDF files, but not load them into 
            tplot variables
            Default: False

        notplot: bool
            Return the data in hash tables instead of creating tplot variables
            Default: False

        no_update: bool
            If set, only load data from your local cache
            Default: False

        time_clip: bool
            Time clip the variables to exactly the range specified in the trange keyword
            Default; False

    Returns
    ----------

        List of tplot variables created.

    Examples
    ----------

        >>> import pyspdedas
        >>> from pytplot import tplot
        >>> uleis_vars = pyspedas.ace.uleis(trange=['2018-11-5', '2018-11-6'])
        >>> tplot(['H_S1', 'H_S2', 'H_S3', 'H_S4', 'H_S5'])

    """
    return load(instrument='ule', trange=trange, datatype=datatype, suffix=suffix, get_support_data=get_support_data, varformat=varformat, varnames=varnames, downloadonly=downloadonly, notplot=notplot, time_clip=time_clip, no_update=no_update)


def sepica(trange=['2004-11-5', '2004-11-6'],
        datatype='h2',
        suffix='',  
        get_support_data=False, 
        varformat=None,
        varnames=[],
        downloadonly=False,
        notplot=False,
        no_update=False,
        time_clip=False):
    """
    Load data from the ACE Solar Energetic Particle Ionic Charge Analyzer (SEPICA)
    
    Parameters
    ----------

        trange : list of str
            time range of interest [starttime, endtime] with the format 
            'YYYY-MM-DD','YYYY-MM-DD'] or to specify more or less than a day 
            ['YYYY-MM-DD/hh:mm:ss','YYYY-MM-DD/hh:mm:ss']
            Default: ['2004-11-5', '2004-11-6']

        datatype: str
            Data type; Valid options:
                h2: 1-Hour Level 2 Data
            Defalut: 'h2'

        suffix: str
            The tplot variable names will be given this suffix.  By default, 
            no suffix is added.
            Default: ''

        get_support_data: bool
            Data with an attribute "VAR_TYPE" with a value of "support_data"
            will be loaded into tplot.  By default, only loads in data with a 
            "VAR_TYPE" attribute of "data".
            Default: False

        varformat: str
            The file variable formats to load into tplot.  Wildcard character
            "*" is accepted.  By default, all variables are loaded in.
            Default: None

        varnames: list of str
            List of variable names to load (if not specified,
            all data variables are loaded)
            Default: []

        downloadonly: bool
            Set this flag to download the CDF files, but not load them into 
            tplot variables
            Default: False

        notplot: bool
            Return the data in hash tables instead of creating tplot variables
            Default: False

        no_update: bool
            If set, only load data from your local cache
            Default: False

        time_clip: bool
            Time clip the variables to exactly the range specified in the trange keyword
            Default: False

    Returns
    ----------
        List of tplot variables created.

    Example:
    ---------- 
        >>> import pyspedas
        >>> from pytplot import tplot   
        >>> sepica_vars = pyspedas.ace.sepica(trange=['2004-11-5', '2004-11-6'])
        >>> tplot(['H1', 'H2', 'H3'])

    """
    return load(instrument='sep', trange=trange, datatype=datatype, suffix=suffix, get_support_data=get_support_data, varformat=varformat, varnames=varnames, downloadonly=downloadonly, notplot=notplot, time_clip=time_clip, no_update=no_update)


def swics(trange=['2018-11-5', '2018-11-6'],
        datatype='sw2_h3',
        suffix='',  
        get_support_data=False, 
        varformat=None,
        varnames=[],
        downloadonly=False,
        notplot=False,
        no_update=False,
        time_clip=False):
    """
    This function loads data from the Solar Wind Ion Composition Spectrometer (SWICS)
    
    Parameters
    ----------
        trange : list of str
            time range of interest [starttime, endtime] with the format 
            'YYYY-MM-DD','YYYY-MM-DD'] or to specify more or less than a day 
            ['YYYY-MM-DD/hh:mm:ss','YYYY-MM-DD/hh:mm:ss']
            Default: ['2018-11-5', '2018-11-6']

        datatype: str
            Data type; Valid options:
                sw2_h3: (default) SWICS 2.0 Solar Wind 2-Hour Level 2 Data
                swi_h2: SWICS 1.1 Solar Wind 1-Hour Level 2 Data
                swi_h3: SWICS 1.1 Solar Wind 2-Hour Level 2 Data
                swi_h4: SWICS 1.1 Solar Wind 1-Day Level 2 Data 
                swi_h5: SWICS 1.1 Solar Wind 2-Hour Level 2 Q-state distributions 
                swi_h6: Solar Wind Protons 12-min Level 2 Data
            Default: 'sw2_h3'

        suffix: str
            The tplot variable names will be given this suffix.  By default, 
            no suffix is added.
            Default: ''

        get_support_data: bool
            Data with an attribute "VAR_TYPE" with a value of "support_data"
            will be loaded into tplot.  By default, only loads in data with a 
            "VAR_TYPE" attribute of "data".
            Default: False

        varformat: str
            The file variable formats to load into tplot.  Wildcard character
            "*" is accepted.  By default, all variables are loaded in.
            Default: None

        varnames: list of str
            List of variable names to load (if not specified,
            all data variables are loaded)
            Default: []

        downloadonly: bool
            Set this flag to download the CDF files, but not load them into 
            tplot variables
            Default: False

        notplot: bool
            Return the data in hash tables instead of creating tplot variables
            Default: False

        no_update: bool
            If set, only load data from your local cache
            Default: False

        time_clip: bool
            Time clip the variables to exactly the range specified in the trange keyword
            Default: False

    Returns
    ----------
        List of tplot variables created.

    Example:
    ---------- 
        >>> import pyspedas
        >>> from pytplot import tplot  
        >>> swi_vars = pyspedas.ace.swics(trange=['2018-11-5', '2018-11-6'])
        >>> tplot(['vHe2', 'vthHe2'])

    """
    return load(instrument='swics', trange=trange, datatype=datatype, suffix=suffix, get_support_data=get_support_data, varformat=varformat, varnames=varnames, downloadonly=downloadonly, notplot=notplot, time_clip=time_clip, no_update=no_update)


def datasets(instrument=None, label=True):
    return find_datasets(mission='ACE', instrument=instrument, label=label)
