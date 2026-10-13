import { onMount } from "solid-js";
import { Chart, Title, Tooltip, Legend, Colors } from "chart.js";
import { Pie, Bar } from "solid-chartjs";
import { useNavigate } from "@solidjs/router";
import "./comparison.css";

export default function Comparison() {
  const navigate = useNavigate();
  onMount(() => {
    Chart.register(Title, Tooltip, Legend, Colors);
  });

  // accuracy
  const chartData = {
    labels: ["RNN", "LSTM", "GRU", "BERT"],
    datasets: [
      {
        label: "Model Accuracy on Text-to-Tect Sequence Classification",
        data: [66, 80, 77, 87],
        backgroundColor: [
          "#ff0000",
          "#00ff00",
          "#0000ff",
          "#ffff00",
          "#ff00ff",
        ],
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: {
        beginAtZero: true,
      },
    },
  };

  return (
    <div class="comparison-container">
      <div class="chart-container">
      <button class="button2" onClick={() => navigate("/glob")}>Go Back</button>
        <Bar data={chartData} options={chartOptions} />
      </div>
      <p>
        As updated on 1st January 2024
      </p>
    </div>
  );
}
