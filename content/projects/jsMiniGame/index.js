const elApp = document.getElementById("app");
const FPS = 10;
let totalIncome = 0;
let totalOutcome = 0;

//add a new row with the values that user has set
const addIncomeOutcome = (type) => {
  const amount = elAmountInput.value;
  if (amount <= 0) {
    setTimeout(() => {
      elAmountHidden.classList.toggle("hidden");
    }, 1000);
    elAmountHidden.classList.remove("hidden");
    elAmountInput.focus();
    return;
  }
  const description = elDescInput.value;
  if (description.length <= 0) {
    setTimeout(() => {
      elDescHidden.classList.toggle("hidden");
    }, 1000);
    elDescHidden.classList.remove("hidden");
    elDescInput.focus();
    return;
  }
  const date = getDateOfToday();
  let all_content =
    type === "outcome"
      ? [formatDate(date), `-${formatNumber(amount)}`, description]
      : [formatDate(date), formatNumber(amount), description];
  const alltr = document.querySelectorAll("tr");
  const totInOut = alltr[alltr.length - 1];
  totInOut.remove();
  createTr(all_content, type);
  elTbody.append(totInOut);
  type === "income"
    ? (totalIncome += Number(amount))
    : (totalOutcome -= Number(amount));
  elAmountInput.value = "";
  elDescInput.value = "";
};

//format the date according to the French standard
const formatDate = (date) => {
  return Intl.DateTimeFormat("fr-FR", {
    dateStyle: "short",
    timeStyle: "long"
  }).format(date);
};

//format amount according to the French standard
const formatNumber = (number) => {
  return Intl.NumberFormat("fr-FR", {
    style: "currency",
    currency: "EUR"
  }).format(number);
};
// Get time of the day
const getDateOfToday = () => {
  return new Date();
};
// create tag
const createElement = (
  tag,
  content = null,
  style,
  placeholder = null,
  type = null,
  parent
) => {
  const elElement = document.createElement(tag);
  elElement.textContent = content;
  elElement.type = type;
  elElement.placeholder = placeholder;
  if (style !== "") {
    style.forEach((element) => {
      elElement.classList.add(element);
    });
  }
  parent.appendChild(elElement);
  return elElement;
};

// create a specific tr tag for the table
const createTr = (content, type) => {
  const elTr = document.createElement("tr");
  const elTd = document.createElement("td");
  const fill = document.createElement("td");
  /*if it's an income we place values in the first td tag
    then we just create an empty td to fill the row otherwise we let the first td empty
    et place values in the second td tag <-- income
    */
  if (type === "income") {
    content.forEach((element) => {
      const span = document.createElement("span");
      span.classList.add("block");
      span.classList.add("text-green-500");
      span.textContent = element;
      elTd.appendChild(span);
    });
    const child_span = elTd.childNodes; // pour mettre la date à droite
    child_span[0].classList.add("text-right", "text-slate-500");
    child_span[1].classList.add("text-left", "font-bold");
    child_span[2].classList.add("text-left");
    elTr.appendChild(elTd);
    elTr.appendChild(fill);
  } else if (type === "outcome") {
    elTr.appendChild(fill);
    content.forEach((element) => {
      const span = document.createElement("span");
      span.classList.add("block");
      span.textContent = element;
      elTd.appendChild(span);
    });
    const child_span = elTd.childNodes; // pour mettre la date à droite
    child_span[0].classList.add("text-right", "text-white");
    child_span[1].classList.add("text-left", "font-bold", "text-red-500");
    child_span[2].classList.add("text-left", "text-red-500");
    elTr.appendChild(elTd);
  } else if (type === "basic") {
    content.forEach((element) => {
      const td = document.createElement("td");
      td.textContent = element;
      td.classList.add("font-bold");
      elTr.appendChild(td);
    });
  }
  elTr.classList.add("even:bg-slate-300", "odd:bg-slate-600");
  elTbody.appendChild(elTr);
  return elTr;
};

const elDiv = createElement(
  "div",
  "",
  ["flex", "justify-around", "items-center", "w-full", "ml-auto", "mr-auto"],
  "",
  "",
  elApp
);

const elDivIncome = createElement("div", "", "", "", "", elDiv);

const elIncomeButton = createElement(
  "button",
  "INCOME",
  [
    "bg-green-500",
    "p-1",
    "rounded",
    "text-white",
    "shadow-lg",
    "shadow-green-500/50"
  ],
  "",
  "",
  elDivIncome
);

const elAmountDiv = createElement(
  "div",
  "",
  ["flex", "flex-col"],
  "",
  "",
  elDiv
);

const elAmountSpan = createElement(
  "span",
  "Amount",
  ["text-center", "font-bold"],
  "",
  "",
  elAmountDiv
);

const elAmountInput = createElement(
  "input",
  "",
  ["rounded", "border-slate-300", "border-2", "outline-none"],
  "0",
  "number",
  elAmountDiv
);
elAmountInput.setAttribute("min", "0");

const elAmountHidden = createElement(
  "span",
  "No number found",
  ["text-red-500", "font-bold", "hidden", "text-center"],
  "",
  "",
  elAmountDiv
);

const elDescDiv = createElement("div", "", ["flex", "flex-col"], "", "", elDiv);

const elDescSpan = createElement(
  "span",
  "Description",
  ["text-center", "font-bold"],
  "",
  "",
  elDescDiv
);

const elDescInput = createElement(
  "input",
  "",
  ["rounded", "border-slate-300", "border-2", "outline-none"],
  "Short description...",
  "text",
  elDescDiv
);
const elDescHidden = createElement(
  "span",
  "Empty field",
  ["text-red-500", "font-bold", "hidden", "text-center"],
  "",
  "",
  elDescDiv
);

const elDivOutcome = createElement("div", "", "", "", "", elDiv);

const elOutcomeButton = createElement(
  "button",
  "OUTCOME",
  [
    "bg-red-500",
    "p-1",
    "rounded",
    "text-white",
    "shadow-lg",
    "shadow-red-500/50"
  ],
  "",
  "",
  elDivOutcome
);

// Table section
const divOfTable = document.createElement("div");
divOfTable.classList.add("flex", "justify-center", "mt-10");
elApp.appendChild(divOfTable);
const elTable = document.createElement("table");
elTable.classList.add("text-center", "w-full");
divOfTable.appendChild(elTable);

const elthead = document.createElement("thead");
elTable.appendChild(elthead);

const trOfThead = document.createElement("tr");
trOfThead.classList.add("text-xl");
elthead.appendChild(trOfThead);

const theadIncome = createElement(
  "th",
  "INCOME",
  ["bg-green-500", "text-white", "p-2"],
  "",
  "",
  trOfThead
);
const theadOutcome = createElement(
  "th",
  "OUTCOME",
  ["bg-red-500", "text-white", "p-2"],
  "",
  "",
  trOfThead
);
const elTbody = document.createElement("tbody");
elTable.appendChild(elTbody);

const totalIncomeOutcome = createTr(
  ["Total Income : 0", "Total Outcome : 0"],
  "basic"
);
totalIncomeOutcome.classList.add("text-white");

// End Table section
const elBalance = createElement(
  "p",
  "Balance : 0",
  ["text-2xl", "text-center", "mt-10", "font-bold"],
  "",
  "",
  elApp
);

// Update different values
const UpdateView = () => {
  totalIncomeOutcome.firstChild.textContent = `Total Income : ${formatNumber(
    totalIncome
  )}`;
  totalIncomeOutcome.lastChild.textContent = `Total Outcome : ${formatNumber(
    totalOutcome
  )}`;

  let balance = totalIncome + totalOutcome;
  elBalance.textContent = `BALANCE : ${formatNumber(balance)}`;
  if (balance < 0) {
    elBalance.classList.add("text-red-500");
    elBalance.classList.remove("text-green-600", "text-black");
  } else if (balance === 0) {
    elBalance.classList.add("text-black");
    elBalance.classList.remove("text-green-600", "text-red-500");
  } else {
    elBalance.classList.add("text-green-600");
    elBalance.classList.remove("text-red-500", "text-black");
  }
  setTimeout(UpdateView, 1000 / FPS);
};
// Event section
elAmountInput.addEventListener("input", (event) => {
  if (event.data !== ".") {
    elAmountInput.value = elAmountInput.value.replace(/[^.\d]/g, ""); // permet d'écrire des nombres seulement (bonus 1)
  }
});

elIncomeButton.addEventListener("click", () => {
  addIncomeOutcome("income");
});
elOutcomeButton.addEventListener("click", () => {
  addIncomeOutcome("outcome");
});

// End event section
UpdateView();
