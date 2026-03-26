// TradeForm.jsx — persistent selections + GTD + broker-aware success/error toast
'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  Button, Col, Form, Row, Alert, Card, Spinner,
} from 'react-bootstrap';
import AsyncSelect from 'react-select/async';
import api from './api';

// helpers
const onlyDigits = (v) => (v ?? '').replace(/[^\d]/g, '');
const toIntOr = (v, fallback = 1) => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

const TRADE_FORM_STORAGE_KEY = 'woi-trade-form-v4';

const detectUserId = () => {
  if (typeof window === 'undefined') return '';
  const a = window.localStorage.getItem('mb_logged_in_userid_v1') || '';
  const b = window.localStorage.getItem('mb_user') || '';
  const c = window.localStorage.getItem('mb_logged_in_userid') || '';
  return (a || b || c || '').replace(/(^"|"$)/g, '');
};

const loadSavedForm = () => {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(TRADE_FORM_STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
};

const todayInputDate = () => {
  const dt = new Date();
  const y = dt.getFullYear();
  const m = String(dt.getMonth() + 1).padStart(2, '0');
  const d = String(dt.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
};

const formatGoodTillDate = (yyyyMmDd) => {
  if (!yyyyMmDd) return '';
  const [y, m, d] = yyyyMmDd.split('-');
  if (!y || !m || !d) return '';

  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const mm = Number(m);
  if (!mm || mm < 1 || mm > 12) return '';

  return `${d}-${months[mm - 1]}-${y}`;
};

const extractBrokerResultSummary = (data) => {
  if (!data) {
    return { ok: false, message: 'Empty response from server.' };
  }

  if (typeof data.status === 'string') {
    const ok = data.status.toUpperCase() === 'SUCCESS';
    return {
      ok,
      message: data.message || (ok ? 'Order placed successfully.' : 'Order failed.'),
    };
  }

  if (data.responses && typeof data.responses === 'object') {
    const entries = Object.entries(data.responses);
    if (!entries.length) {
      return { ok: false, message: 'No broker response entries found.' };
    }

    const failed = entries.filter(([, r]) => String(r?.status || '').toUpperCase() !== 'SUCCESS');

    if (failed.length > 0) {
      const parts = failed.map(([clientId, r]) => {
        const msg = r?.message || r?.error || 'Order failed';
        const code = r?.errorcode ? ` (${r.errorcode})` : '';
        return `${clientId}: ${msg}${code}`;
      });
      return {
        ok: false,
        message: parts.join(' | '),
      };
    }

    const successParts = entries.map(([clientId, r]) => {
      const uoid = r?.uniqueorderid ? ` [${r.uniqueorderid}]` : '';
      return `${clientId}${uoid}`;
    });

    return {
      ok: true,
      message: `Order placed successfully: ${successParts.join(', ')}`,
    };
  }

  return {
    ok: false,
    message: data.message || data.error || 'Unexpected response from server.',
  };
};

export default function TradeForm() {
  const saved = loadSavedForm();

  const [action, setAction] = useState(saved?.action ?? 'buy');
  const [productType, setProductType] = useState(saved?.productType ?? 'DELIVERY');
  const [orderType, setOrderType] = useState(saved?.orderType ?? 'LIMIT');
  const [qtySelection, setQtySelection] = useState(saved?.qtySelection ?? 'manual');
  const [groupAcc, setGroupAcc] = useState(saved?.groupAcc ?? false);
  const [diffQty, setDiffQty] = useState(saved?.diffQty ?? false);
  const [multiplier, setMultiplier] = useState(saved?.multiplier ?? false);

  const [qty, setQty] = useState(saved?.qty ?? '1');
  const [exchange, setExchange] = useState(saved?.exchange ?? 'nse');
  const [symbol, setSymbol] = useState(saved?.symbol ?? null);
  const [price, setPrice] = useState(saved?.price ?? 0);
  const [trigPrice, setTrigPrice] = useState(saved?.trigPrice ?? 0);
  const [disclosedQty, setDisclosedQty] = useState(saved?.disclosedQty ?? 0);

  const [timeForce, setTimeForce] = useState(saved?.timeForce ?? 'DAY');
  const [goodTillDate, setGoodTillDate] = useState(saved?.goodTillDate ?? todayInputDate());
  const [amo, setAmo] = useState(saved?.amo ?? false);

  const [clients, setClients] = useState([]);
  const [selectedClients, setSelectedClients] = useState(saved?.selectedClients ?? []);

  const [groups, setGroups] = useState([]);
  const [selectedGroups, setSelectedGroups] = useState(saved?.selectedGroups ?? []);

  const [perClientQty, setPerClientQty] = useState(saved?.perClientQty ?? {});
  const [perGroupQty, setPerGroupQty] = useState(saved?.perGroupQty ?? {});

  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState(null);

  useEffect(() => {
    const userid = detectUserId();
    const headers = userid ? { 'x-user-id': userid } : {};
    const params = userid ? { userid } : {};

    const loadClients = async () => {
      try {
        const res = await api.get('/clients', { params, headers });
        const data = res?.data;
        const list = Array.isArray(data?.clients) ? data.clients : (Array.isArray(data) ? data : []);
        setClients(list);
      } catch {
        setClients([]);
      }
    };

    const loadGroups = async () => {
      try {
        const res = await api.get('/groups', { params, headers });
        const data = res?.data;
        const list = Array.isArray(data?.groups) ? data.groups : (Array.isArray(data) ? data : []);

        const normalized = (list || []).map((g) => {
          const group_name = g?.group_name ?? g?.name ?? g?.group ?? g?.groupName ?? g?.title ?? '';
          const membersRaw = g?.members ?? g?.clients ?? g?.client_ids ?? g?.clientIds ?? g?.accounts ?? [];
          const members = Array.isArray(membersRaw)
            ? membersRaw
            : (typeof membersRaw === 'string'
              ? membersRaw.split(',').map((s) => s.trim()).filter(Boolean)
              : []);
          const groupMultiplier = Number(g?.multiplier ?? g?.groupMultiplier ?? g?.mult ?? 1) || 1;

          return {
            ...g,
            group_name: String(group_name || '').trim(),
            no_of_clients: Number(g?.no_of_clients ?? members.length ?? 0) || 0,
            multiplier: groupMultiplier,
            members,
          };
        }).filter((g) => g.group_name);

        setGroups(normalized);
      } catch {
        setGroups([]);
      }
    };

    loadClients();
    loadGroups();
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;

    const formState = {
      action,
      productType,
      orderType,
      qtySelection,
      groupAcc,
      diffQty,
      multiplier,
      qty,
      exchange,
      symbol,
      price,
      trigPrice,
      disclosedQty,
      timeForce,
      goodTillDate,
      amo,
      selectedClients,
      selectedGroups,
      perClientQty,
      perGroupQty,
    };

    try {
      window.localStorage.setItem(TRADE_FORM_STORAGE_KEY, JSON.stringify(formState));
    } catch {
      // ignore
    }
  }, [
    action,
    productType,
    orderType,
    qtySelection,
    groupAcc,
    diffQty,
    multiplier,
    qty,
    exchange,
    symbol,
    price,
    trigPrice,
    disclosedQty,
    timeForce,
    goodTillDate,
    amo,
    selectedClients,
    selectedGroups,
    perClientQty,
    perGroupQty,
  ]);

  useEffect(() => {
    if (!clients.length) return;
    setSelectedClients((prev) =>
      (prev || []).filter((cid) => clients.some((c) => c.client_id === cid))
    );
    setPerClientQty((prev) => {
      const validIds = new Set(clients.map((c) => c.client_id));
      return Object.fromEntries(
        Object.entries(prev || {}).filter(([cid]) => validIds.has(cid))
      );
    });
  }, [clients]);

  useEffect(() => {
    if (!groups.length) return;
    setSelectedGroups((prev) =>
      (prev || []).filter((gn) => groups.some((g) => g.group_name === gn))
    );
    setPerGroupQty((prev) => {
      const validNames = new Set(groups.map((g) => g.group_name));
      return Object.fromEntries(
        Object.entries(prev || {}).filter(([gn]) => validNames.has(gn))
      );
    });
  }, [groups]);

  const loadSymbolOptions = async (inputValue) => {
    if (!inputValue || inputValue.length < 1) return [];
    const res = await api.get('/search_symbols', { params: { q: inputValue, exchange } });
    const results = res.data?.results || [];
    return results.map((r) => ({
      value: r.id ?? r.value ?? r.symbol ?? r.text,
      label: r.text ?? r.label ?? String(r.id),
    }));
  };

  const isStopOrder = orderType === 'STOPLOSS' || orderType === 'SL MARKET';

  const selectedClientMap = useMemo(
    () => new Map((clients || []).map((c) => [c.client_id, c])),
    [clients]
  );

  const submit = async (e) => {
    e.preventDefault();

    if (groupAcc) {
      if (selectedGroups.length === 0) {
        setToast({ variant: 'warning', text: 'Please select at least one group.' });
        return;
      }
    } else if (selectedClients.length === 0) {
      setToast({ variant: 'warning', text: 'Please select at least one client.' });
      return;
    }

    if (!symbol || !symbol.value) {
      setToast({ variant: 'warning', text: 'Please select a symbol before placing the order.' });
      return;
    }

    if (timeForce === 'GTD') {
      if (!goodTillDate) {
        setToast({ variant: 'warning', text: 'Please select Good Till Date.' });
        return;
      }
      const today = todayInputDate();
      if (goodTillDate < today) {
        setToast({ variant: 'warning', text: 'Good Till Date cannot be earlier than today.' });
        return;
      }
    }

    const safeSingleQty = qtySelection === 'auto' ? 0 : toIntOr(qty, 1);

    const safePerClientQty = (!groupAcc && diffQty)
      ? Object.fromEntries(selectedClients.map((cid) => [cid, toIntOr(perClientQty[cid], 1)]))
      : {};

    const safePerGroupQty = (groupAcc && diffQty)
      ? Object.fromEntries(selectedGroups.map((gn) => [gn, toIntOr(perGroupQty[gn], 1)]))
      : {};

    setBusy(true);
    try {
      const payload = {
        groupacc: groupAcc,
        groups: selectedGroups,
        clients: selectedClients,
        action: action?.toUpperCase(),
        ordertype: orderType?.toUpperCase(),
        producttype: productType?.toUpperCase(),
        orderduration: timeForce?.toUpperCase(),
        exchange: exchange?.toUpperCase(),
        symbol: symbol?.value || '',
        price: Number(price) || 0,
        triggerprice: Number(trigPrice) || 0,
        disclosedquantity: Number(disclosedQty) || 0,
        amoorder: amo ? 'Y' : 'N',
        goodtilldate: timeForce === 'GTD' ? formatGoodTillDate(goodTillDate) : '',
        qtySelection,
        quantityinlot: safeSingleQty,
        perClientQty: safePerClientQty,
        perGroupQty: safePerGroupQty,
        diffQty,
        multiplier,
      };

      const resp = await api.post('/place_order', payload);
      const summary = extractBrokerResultSummary(resp?.data);

      setToast({
        variant: summary.ok ? 'success' : 'danger',
        text: summary.message,
      });
    } catch (err) {
      const backendMsg =
        err.response?.data?.detail ||
        err.response?.data?.message ||
        err.response?.data?.error ||
        err.message;

      setToast({
        variant: 'danger',
        text: 'Error: ' + backendMsg,
      });
    } finally {
      setBusy(false);
    }
  };

  const resetForm = () => {
    try {
      if (typeof window !== 'undefined') {
        window.localStorage.removeItem(TRADE_FORM_STORAGE_KEY);
      }
    } catch {
      // ignore
    }
    window.location.reload();
  };

  return (
    <Card className="shadow-sm cardPad blueTone">
      <Form onSubmit={submit}>
        <div className="formSection">
          <Row className="g-2 align-items-center">
            <Col xs="auto" className="d-flex align-items-center flex-wrap gap-3">
              <Form.Label className="mb-0 fw-semibold">Action</Form.Label>
              <Form.Check
                inline
                type="radio"
                name="action"
                id="buy"
                label="BUY"
                checked={action === 'buy'}
                onChange={() => setAction('buy')}
              />
              <Form.Check
                inline
                type="radio"
                name="action"
                id="sell"
                label="SELL"
                checked={action === 'sell'}
                onChange={() => setAction('sell')}
              />
            </Col>
          </Row>
        </div>

        <div className="formSection">
          <Row className="g-2 align-items-center">
            <Col xs="auto" className="d-flex align-items-center flex-wrap gap-3">
              <Form.Label className="mb-0 fw-semibold">Product</Form.Label>
              {['VALUEPLUS', 'DELIVERY', 'NORMAL', 'SELLFROMDP', 'BTST', 'MTF'].map((pt) => (
                <Form.Check
                  key={pt}
                  inline
                  type="radio"
                  name="productType"
                  label={pt === 'VALUEPLUS' ? 'INTRADAY' : pt}
                  checked={productType === pt}
                  onChange={() => setProductType(pt)}
                />
              ))}
            </Col>
          </Row>
        </div>

        <div className="formSection">
          <Row className="g-2 align-items-center">
            <Col xs="auto" className="d-flex align-items-center flex-wrap gap-3">
              <Form.Label className="mb-0 fw-semibold">Order Type</Form.Label>
              {['LIMIT', 'MARKET', 'STOPLOSS', 'SL MARKET'].map((ot) => (
                <Form.Check
                  key={ot}
                  inline
                  type="radio"
                  name="orderType"
                  label={ot.replace('SL MARKET', 'SL_MARKET')}
                  checked={orderType === ot}
                  onChange={() => setOrderType(ot)}
                />
              ))}
            </Col>
          </Row>
        </div>

        <div className="formSection">
          <Row>
            <Col xs={12}>
              {!groupAcc ? (
                <>
                  <Form.Label className="label-tight">Select Clients</Form.Label>
                  <Form.Select
                    multiple
                    size={8}
                    value={selectedClients}
                    onChange={(e) =>
                      setSelectedClients(Array.from(e.target.selectedOptions).map((o) => o.value))
                    }
                  >
                    {(clients || []).map((c) => (
                      <option key={c.client_id} value={c.client_id}>
                        {c.name} : {c.client_id}
                      </option>
                    ))}
                  </Form.Select>

                  {diffQty && (
                    <div className="mt-2">
                      <Form.Label className="fw-semibold small text-primary">
                        Enter Quantity per Client
                      </Form.Label>
                      {selectedClients.length === 0 ? (
                        <div className="text-muted small">Select clients to assign quantities.</div>
                      ) : (
                        selectedClients.map((cid) => {
                          const client = selectedClientMap.get(cid);
                          return (
                            <Row key={cid} className="align-items-center mb-1">
                              <Col xs={6}>
                                <div className="text-muted small">{client?.name || cid}</div>
                              </Col>
                              <Col xs={6}>
                                <Form.Control
                                  type="number"
                                  min="1"
                                  value={perClientQty[cid] || ''}
                                  onChange={(e) =>
                                    setPerClientQty((prev) => ({ ...prev, [cid]: e.target.value }))
                                  }
                                  placeholder="Qty"
                                />
                              </Col>
                            </Row>
                          );
                        })
                      )}
                    </div>
                  )}
                </>
              ) : (
                <>
                  <Form.Label className="label-tight">Select Groups</Form.Label>
                  <div className="border rounded p-2">
                    {groups.length === 0 ? (
                      <div className="text-muted">No groups found.</div>
                    ) : (
                      groups.map((g) => (
                        <Form.Check
                          key={g.group_name}
                          type="checkbox"
                          id={`group_${g.group_name}`}
                          label={`${g.group_name} (${g.no_of_clients} clients, x${g.multiplier})`}
                          checked={selectedGroups.includes(g.group_name)}
                          onChange={(e) => {
                            const chk = e.target.checked;
                            setSelectedGroups((prev) =>
                              chk ? [...prev, g.group_name] : prev.filter((x) => x !== g.group_name)
                            );
                          }}
                        />
                      ))
                    )}
                  </div>

                  {diffQty && (
                    <div className="mt-2">
                      <Form.Label className="fw-semibold small text-primary">
                        Enter Quantity per Group
                      </Form.Label>
                      {selectedGroups.length === 0 ? (
                        <div className="text-muted small">Select groups to assign quantities.</div>
                      ) : (
                        selectedGroups.map((gn) => (
                          <Row key={gn} className="align-items-center mb-1">
                            <Col xs={6}>
                              <div className="text-muted small">{gn}</div>
                            </Col>
                            <Col xs={6}>
                              <Form.Control
                                type="number"
                                min="1"
                                value={perGroupQty[gn] || ''}
                                onChange={(e) =>
                                  setPerGroupQty((prev) => ({ ...prev, [gn]: e.target.value }))
                                }
                                placeholder="Qty"
                              />
                            </Col>
                          </Row>
                        ))
                      )}
                    </div>
                  )}
                </>
              )}
            </Col>
          </Row>
        </div>

        <div className="formSection">
          <Row className="g-2 mb-2 align-items-end">
            <Col md={5}>
              <Form.Label className="label-tight">Qty</Form.Label>
              <Form.Control
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                disabled={qtySelection === 'auto' || diffQty}
                value={qty}
                onChange={(e) => setQty(onlyDigits(e.target.value))}
                onBlur={() => setQty(String(Math.max(1, parseInt(qty || '1', 10) || 1)))}
              />
              {diffQty && (
                <div className="form-text">Disabled because “Diff. Qty.” is ON.</div>
              )}
            </Col>

            <Col md={7}>
              <div className="d-flex align-items-center flex-wrap gap-3 mb-1">
                <Form.Label className="mb-0 fw-semibold">Entity</Form.Label>
                <Form.Check
                  inline
                  type="checkbox"
                  id="groupAcc"
                  label="Group Acc"
                  checked={groupAcc}
                  onChange={(e) => {
                    const checked = e.target.checked;
                    setGroupAcc(checked);
                    setSelectedGroups([]);
                    setSelectedClients([]);
                    setPerGroupQty({});
                    setPerClientQty({});
                  }}
                />
                <Form.Check
                  inline
                  type="checkbox"
                  id="diffQty"
                  label="Diff. Qty."
                  checked={diffQty}
                  onChange={(e) => setDiffQty(e.target.checked)}
                />
                <Form.Check
                  inline
                  type="checkbox"
                  id="multiplier"
                  label="Multiplier"
                  checked={multiplier}
                  onChange={(e) => setMultiplier(e.target.checked)}
                />
              </div>

              <div className="d-flex align-items-center flex-wrap gap-3">
                <Form.Label className="mb-0 fw-semibold">Qty Mode</Form.Label>
                <Form.Check
                  inline
                  type="radio"
                  name="qtySel"
                  label="Manual"
                  checked={qtySelection === 'manual'}
                  onChange={() => setQtySelection('manual')}
                />
                <Form.Check
                  inline
                  type="radio"
                  name="qtySel"
                  label="Auto Calculate"
                  checked={qtySelection === 'auto'}
                  onChange={() => setQtySelection('auto')}
                />
              </div>
            </Col>
          </Row>

          <Row className="g-2 mb-2 align-items-end">
            <Col md={5}>
              <Form.Label className="label-tight">Exchange</Form.Label>
              <Form.Select
                value={exchange}
                onChange={(e) => setExchange(e.target.value)}
              >
                {['nse', 'bse', 'nsefo', 'nsecd', 'ncdex', 'mcx', 'bsefo', 'bsecd'].map((x) => (
                  <option key={x} value={x}>
                    {x.toUpperCase()}
                  </option>
                ))}
              </Form.Select>
            </Col>

            <Col md={7}>
              <Form.Label className="label-tight">Symbol</Form.Label>
              <AsyncSelect
                cacheOptions
                defaultOptions={false}
                loadOptions={loadSymbolOptions}
                value={symbol}
                onChange={setSymbol}
                placeholder="Type to search symbol..."
              />
            </Col>
          </Row>

          <Row className="g-2 align-items-end">
            <Col md={5}>
              <Form.Label className="label-tight">Price</Form.Label>
              <Form.Control
                type="number"
                step="0.01"
                value={price}
                onChange={(e) => setPrice(e.target.value)}
              />
            </Col>

            <Col md={7}>
              <Row className="g-2">
                <Col md={6}>
                  <Form.Label className="label-tight">Trig. Price</Form.Label>
                  <Form.Control
                    type="number"
                    step="0.01"
                    value={trigPrice}
                    onChange={(e) => setTrigPrice(e.target.value)}
                    disabled={!isStopOrder}
                  />
                </Col>
                <Col md={6}>
                  <Form.Label className="label-tight">Disclosed Qty</Form.Label>
                  <Form.Control
                    type="number"
                    value={disclosedQty}
                    onChange={(e) => setDisclosedQty(e.target.value)}
                  />
                </Col>
              </Row>
            </Col>
          </Row>
        </div>

        <div className="formSection">
          <Row className="g-2 align-items-center">
            <Col md={12}>
              <div className="d-flex align-items-center flex-wrap gap-3">
                <Form.Label className="mb-0">Order Duration</Form.Label>
                {['DAY', 'IOC', 'GTC', 'GTD'].map((tf) => (
                  <Form.Check
                    key={tf}
                    inline
                    type="radio"
                    name="timeForce"
                    label={tf}
                    checked={timeForce === tf}
                    onChange={() => setTimeForce(tf)}
                  />
                ))}
                <Form.Check
                  inline
                  type="checkbox"
                  id="amo"
                  label="AMO Order"
                  checked={amo}
                  onChange={(e) => setAmo(e.target.checked)}
                />
              </div>

              {timeForce === 'GTD' && (
                <Row className="g-2 mt-2 align-items-end">
                  <Col md={4}>
                    <Form.Label className="label-tight">Good Till Date</Form.Label>
                    <Form.Control
                      type="date"
                      value={goodTillDate}
                      min={todayInputDate()}
                      onChange={(e) => setGoodTillDate(e.target.value)}
                    />
                    <div className="form-text">
                      Payload value: {formatGoodTillDate(goodTillDate) || '-'}
                    </div>
                  </Col>
                </Row>
              )}
            </Col>
          </Row>
        </div>

        <Row className="mt-2">
          <Col className="text-start">
            <div className="btn-nudge">
              <Button type="submit" variant={action === 'buy' ? 'success' : 'danger'} disabled={busy}>
                {busy ? <Spinner size="sm" animation="border" className="me-2" /> : null}
                {action.toUpperCase()}
              </Button>{' '}
              <Button type="button" variant="secondary" onClick={resetForm}>
                Reset
              </Button>
            </div>
          </Col>
        </Row>

        {toast && (
          <Alert variant={toast.variant} onClose={() => setToast(null)} dismissible className="mt-3">
            {toast.text}
          </Alert>
        )}
      </Form>

      <style jsx>{`
        .cardPad { padding: 1rem 2.5rem 2.75rem; }
        @media (min-width: 992px) {
          .cardPad { padding: 1.25rem 2.75rem 3.25rem; }
        }

        .blueTone {
          background: linear-gradient(180deg, #f9fbff 0%, #f3f7ff 100%);
          border: 1px solid #d5e6ff;
          box-shadow: 0 0 0 6px rgba(49, 132, 253, 0.12);
          border-radius: 8px;
        }

        .formSection {
          padding-block: 6px;
          margin: 0 16px 8px;
          border-bottom: 1px dashed #d7e3ff;
        }
        .formSection:last-of-type {
          border-bottom: 0;
          margin-bottom: 0;
          padding-bottom: 0;
        }

        .label-tight { margin-bottom: 4px; }

        :global(input[type="radio"]),
        :global(input[type="checkbox"]) {
          accent-color: #0d6efd;
        }

        .btn-nudge { margin-left: 3rem; padding-bottom: 0.25rem; }

        .text-muted.small { font-size: 0.85rem; }
      `}</style>
    </Card>
  );
}
