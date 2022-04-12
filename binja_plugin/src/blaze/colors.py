from typing import cast

from binaryninja import HighlightColor, HighlightColorStyle, HighlightStandardColor

from .types import CallNodeRating


def lerp(c1: HighlightColor, c2: HighlightColor, amount: float) -> HighlightColor:
    def _lerp(x: int, y: int, a: float) -> int:
        return max(0, min(int(x * (1 - a) + y * a), 255))

    if not (c1.style == c2.style == HighlightColorStyle.CustomHighlightColor):
        raise TypeError(
            'c1 and c2 must both be CustomHighlightColor, not '
            f'({c1.style.name}, {c2.style.name})')

    return HighlightColor(
        red=_lerp(c1.red, c2.red, amount),
        green=_lerp(c1.green, c2.green, amount),
        blue=_lerp(c1.blue, c2.blue, amount),
        alpha=_lerp(c1.alpha, c2.alpha, amount),
    )


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
POI_REACHABLE_MEH_BASE = HighlightColor(red=255, green=255, blue=135)
POI_REACHABLE_GOOD_BASE = HighlightColor(red=255, green=0, blue=0)

########
# ICFG #
########

REGULAR_CALL_NODE = muted(0.8, HighlightStandardColor.YellowHighlightColor)
UNEXPANDABLE_CALL_NODE = HighlightStandardColor.BlackHighlightColor
GROUPING_NODE = HighlightColor(red=171, green=102, blue=227)
GROUP_START = HighlightColor(HighlightStandardColor.GreenHighlightColor)
GROUP_END_CANDIDATE = HighlightColor(HighlightStandardColor.BlueHighlightColor)


def call_node_rated_color(rating: CallNodeRating) -> HighlightColor:
    if rating['tag'] == 'Unreachable':
        return POI_UNREACHABLE

    elif rating['tag'] == 'Reachable':
        score = cast(float, rating.get('score'))
        return lerp(POI_REACHABLE_MEH_BASE, POI_REACHABLE_GOOD_BASE, score)

    else:
        assert False, f'Inexaustive match on CallNodeRating? tag={rating["tag"]}'


def enter_func_node(has_pois: bool = False) -> HighlightColor:
    opacity = 0.8 if has_pois else 1.0
    return muted(opacity, HighlightStandardColor.GreenHighlightColor)


def leave_func_node(has_pois: bool = False) -> HighlightColor:
    opacity = 0.8 if has_pois else 1.0
    return muted(opacity, HighlightStandardColor.BlueHighlightColor)


ICFG_CHANGES_REMOVED = HighlightStandardColor.RedHighlightColor
