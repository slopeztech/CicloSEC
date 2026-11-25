"""Backward-compatible bounded pagination for authenticated DRF list endpoints."""

from typing import Any

from rest_framework.request import Request
from rest_framework.response import Response


class LimitOffsetListMixin:
    default_limit = 50
    max_limit = 100

    def list(self: Any, request: Request, *args: object, **kwargs: object) -> Response:
        if "limit" not in request.query_params and "offset" not in request.query_params:
            queryset = self.filter_queryset(self.get_queryset())
            page = list(queryset)
            serializer = self.get_serializer(page, many=True)
            return Response(serializer.data)

        try:
            limit = int(request.query_params.get("limit", self.default_limit))
            offset = int(request.query_params.get("offset", 0))
        except (TypeError, ValueError):
            return Response(
                {"detail": "limit and offset must be integers."},
                status=400,
            )
        if limit < 1 or limit > self.max_limit:
            return Response(
                {"detail": f"limit must be between 1 and {self.max_limit}."},
                status=400,
            )
        if offset < 0:
            return Response(
                {"detail": "offset must be zero or positive."},
                status=400,
            )

        queryset = self.filter_queryset(self.get_queryset())
        total = queryset.count()
        items = queryset[offset : offset + limit]
        serializer = self.get_serializer(items, many=True)
        return Response(
            {
                "total": total,
                "limit": limit,
                "offset": offset,
                "items": serializer.data,
            }
        )
