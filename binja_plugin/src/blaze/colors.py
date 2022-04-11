from typing import cast

from binaryninja import HighlightColor, HighlightStandardColor

from .types import CallNodeRating


def muted(muteness: float, color: HighlightStandardColor) -> HighlightColor:
    "Mutes a color. 0.0 muteness is totally black. 1.0 is totally color"
    return HighlightColor(
        HighlightStandardColor.BlackHighlightColor,
        color,
        mix=int(min(255, max(0, muteness * 255))))


########
# POIS #
########

POI = HighlightColor(red=150, green=90, blue=90)
POI_PRESENT_TARGET = HighlightColor(HighlightStandardColor.WhiteHighlightColor)
POI_NODE_NOT_FOUND = muted(0.4, HighlightStandardColor.YellowHighlightColor)
POI_UNREACHABLE = HighlightColor(HighlightStandardColor.BlackHighlightColor)
POI_REACHABLE_MEH_BASE = HighlightStandardColor.YellowHighlightColor
POI_REACHABLE_GOOD_BASE = HighlightStandardColor.RedHighlightColor

########
# ICFG #
########

REGULAR_CALL_NODE = muted(0.8, HighlightStandardColor.YellowHighlightColor)
UNEXPANDABLE_CALL_NODE = HighlightStandardColor.BlackHighlightColor
GROUPING_NODE = HighlightStandardColor.MagentaHighlightColor
GROUP_START = HighlightColor(HighlightStandardColor.GreenHighlightColor)
GROUP_END_CANDIDATE = HighlightColor(HighlightStandardColor.BlueHighlightColor)


def call_node_rated_color(rating: CallNodeRating) -> HighlightColor:
    if rating['tag'] == 'Unreachable':
        return POI_UNREACHABLE

    elif rating['tag'] == 'Reachable':
        score = cast(float, rating.get('score'))
        return HighlightColor(
            POI_REACHABLE_MEH_BASE, POI_REACHABLE_GOOD_BASE, mix=int(min(255, max(0, score * 255))))

    else:
        assert False, f'Inexaustive match on CallNodeRating? tag={rating["tag"]}'


def enter_func_node(has_pois: bool = False) -> HighlightColor:
    opacity = 0.8 if has_pois else 1.0
    return muted(opacity, HighlightStandardColor.GreenHighlightColor)


def leave_func_node(has_pois: bool = False) -> HighlightColor:
    opacity = 0.8 if has_pois else 1.0
    return muted(opacity, HighlightStandardColor.BlueHighlightColor)


ICFG_CHANGES_REMOVED = HighlightStandardColor.RedHighlightColor
