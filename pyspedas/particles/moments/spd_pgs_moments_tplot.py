
from pytplot import store_data, options

def spd_pgs_moments_tplot(moments, x=None, prefix='', suffix=''):
    """
    """

    if x is None:
        logging.error('Error, no x-values specified')
        return

    if not isinstance(moments, dict):
        logging.error('Error, the "moments" variable must be a hash table containing the moments')
        return


    for key in moments.keys():
        store_data(prefix + '_' + key + suffix, data={'x': x, 'y': moments[key]})

    options(prefix + '_density' + suffix, 'ysubtitle', '[1/cc]')
    options(prefix + '_velocity' + suffix, 'yrange', [-800, 800])
    options(prefix + '_flux' + suffix, 'yrange', [-1e8, 1e8])

    return [prefix + '_' + key + suffix for key in moments.keys()]
