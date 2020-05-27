# Copyright (C) 2020 Zeropoint Dynamics

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
# ======================================================================
__version__ = "0.0.2.dev0"

__title__ = "angr-zelos-target"
__description__ = "Zelos target for angr / symbion concrete execution."
__url__ = "https://github.com/zeropointdynamics/angr_zelos_target"
__uri__ = __url__
__doc__ = __description__ + " <" + __uri__ + ">"

__author__ = "Zeropoint Dynamics"
__email__ = "zelos@zeropointdynamics.com"

__license__ = "AGPLv3"
__copyright__ = "Copyright (c) 2020 Zeropoint Dynamics"


from .angr_zelos_target import ZelosConcreteTarget, ZelosExplorationTechnique

__all__ = [
    "ZelosConcreteTarget",
    "ZelosExplorationTechnique",
]
