"""Table formatting helpers for output."""

from __future__ import annotations

from typing import List

from .rows import _build_result_rows


def _format_row(row: List[str], widths: List[int]) -> str:
    """Format a markdown table row with padded cells.

    Args:
        row (List[str]): Row values.
        widths (List[int]): Column widths.

    Returns:
        str: Formatted markdown table row.
    """
    padded = [f"{cell:<{widths[i]}}" for i, cell in enumerate(row)]
    return "| " + " | ".join(padded) + " |"


def _build_table_rows(results: List[dict]) -> List[List[str]]:
    """Build markdown table rows for serialized results.

    Args:
        results (List[dict]): Serialized results.

    Returns:
        List[List[str]]: Table rows.
    """
    rows: List[List[str]] = []
    for result in results:
        table_rows = result.get("table_rows")
        if table_rows is None:
            rows.extend(_build_row_cells(_build_result_rows(result)))
        else:
            rows.extend(table_rows)
    return rows


def _build_table_widths(headers: List[str], rows: List[List[str]]) -> List[int]:
    """Compute column widths for a markdown table.

    Args:
        headers (List[str]): Table headers.
        rows (List[List[str]]): Table rows.

    Returns:
        List[int]: Widths for each column.
    """
    widths = [len(header) for header in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    return widths


def _build_table_separator(widths: List[int]) -> str:
    """Build a markdown table separator row.

    Args:
        widths (List[int]): Column widths.

    Returns:
        str: Markdown separator row.
    """
    return "| " + " | ".join("-" * max(3, width) for width in widths) + " |"


def _format_text_row(row: List[str], widths: List[int], indent: str = "  ") -> str:
    """Format a text row with padded columns.

    Args:
        row (List[str]): Row values.
        widths (List[int]): Column widths.
        indent (str): Prefix for the row.

    Returns:
        str: Formatted text row.
    """
    padded = [f"{cell:<{widths[i]}}" for i, cell in enumerate(row)]
    return f"{indent}{'  '.join(padded).rstrip()}"


def _build_text_widths(headers: List[str], rows: List[List[str]]) -> List[int]:
    """Compute column widths for aligned text output.

    Args:
        headers (List[str]): Column headers.
        rows (List[List[str]]): Row values.

    Returns:
        List[int]: Widths for each column.
    """
    widths = [len(header) for header in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    return widths


def _build_row_cells(rows: List[dict]) -> List[List[str]]:
    """Convert row dicts into table cell lists.

    Args:
        rows (List[dict]): Row dicts.

    Returns:
        List[List[str]]: Row cells for tables.
    """
    return [[row["status"], row["message"], row["expected"], row["found"]] for row in rows]


def _build_text_cells(rows: List[dict]) -> List[List[str]]:
    """Convert row dicts into text table cells.

    Args:
        rows (List[dict]): Row dicts.

    Returns:
        List[List[str]]: Row cells for text output.
    """
    return [[row["status"], row["item"], row["expected"], row["found"]] for row in rows]
