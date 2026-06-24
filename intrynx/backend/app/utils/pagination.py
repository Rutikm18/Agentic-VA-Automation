from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select


async def paginate_query(
    db: AsyncSession,
    query: Select,
    page: int,
    page_size: int,
) -> tuple[list, int]:
    """Returns (items, total). Applies OFFSET/LIMIT to `query`."""
    count_query = select(func.count()).select_from(query.subquery())
    total: int = (await db.execute(count_query)).scalar_one()

    offset = (page - 1) * page_size
    result = await db.execute(query.offset(offset).limit(page_size))
    items = result.scalars().all()
    return list(items), total
